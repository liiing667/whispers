import pytest

from whispers.core.args import parse_args
from whispers.core.config import load_config
from whispers.core.scope import load_scope


def _write(path, content="key: value\n"):
    path.write_text(content)


@pytest.fixture(scope="module")
def link_tree(tmp_path_factory):
    """
    Fixed symlink tree for scope boundary acceptance.

    root/
      real/
        inside.yml            real in-root file
        sub/deep.yml          real nested file
      link_to_file.yml        symlink to a file outside of root
      link_to_dir             symlink to a directory outside of root
      loop                    self-referencing symlink (symlink loop)
      broken                  dangling symlink (resolution failure)
      excluded.yml            real file matched by the exclude rule
      excluded_link.yml       symlink to excluded.yml (exclude bypass attempt)
      link_inside.yml         symlink to a real file inside of root
    outside/
      secret.yml              credential that must never enter reports
    """
    base = tmp_path_factory.mktemp("scope_links")
    root = base / "root"
    outside = base / "outside"
    real = root / "real"
    nested = real / "sub"
    nested.mkdir(parents=True)
    outside.mkdir()

    _write(real / "inside.yml")
    _write(nested / "deep.yml")
    _write(root / "excluded.yml", "excluded: value\n")
    _write(outside / "secret.yml", "secret: AKIAIOSFODNN7EXAMPLE\n")

    (root / "link_to_file.yml").symlink_to(outside / "secret.yml")
    (root / "link_to_dir").symlink_to(outside)
    (root / "loop").symlink_to(root / "loop")
    (root / "broken").symlink_to(outside / "does_not_exist.yml")
    (root / "excluded_link.yml").symlink_to(root / "excluded.yml")
    (root / "link_inside.yml").symlink_to(real / "inside.yml")

    root_link = base / "root_link"
    root_link.symlink_to(root)

    return {"base": base, "root": root, "root_link": root_link, "outside": outside}


def _scope(link_tree, *extra_argv):
    argv = list(extra_argv) + [link_tree["root"].as_posix()]
    args = parse_args(argv)
    config = load_config(args)
    return [path.resolve() for path in load_scope(args, config)]


def test_real_files_remain_in_scope(link_tree):
    root = link_tree["root"]
    scope = _scope(link_tree)

    assert (root / "real" / "inside.yml").resolve() in scope
    assert (root / "real" / "sub" / "deep.yml").resolve() in scope


def test_out_of_root_file_symlink_produces_no_pairs(link_tree):
    scope = _scope(link_tree)

    assert link_tree["outside"].resolve() not in scope
    assert all(link_tree["outside"].resolve() not in path.parents for path in scope)
    assert all(path.name != "secret.yml" for path in scope)


def test_out_of_root_directory_symlink_produces_no_pairs(link_tree):
    scope = _scope(link_tree)

    assert all("link_to_dir" not in path.parts for path in scope)


def test_symlink_loop_produces_no_pairs(link_tree):
    scope = _scope(link_tree)

    assert all(path.name != "loop" for path in scope)


def test_broken_symlink_produces_no_pairs(link_tree):
    scope = _scope(link_tree)

    assert all(path.name != "broken" for path in scope)


def test_in_root_symlink_target_is_deduped(link_tree):
    root = link_tree["root"]
    scope = _scope(link_tree)

    target = (root / "real" / "inside.yml").resolve()
    assert scope.count(target) == 1


def test_exclude_semantics_match_resolved_targets(link_tree):
    scope = _scope(link_tree, "-F", r".*excluded\.yml")

    assert all(path.name not in ("excluded.yml", "excluded_link.yml") for path in scope)


def test_exclude_cannot_be_bypassed_through_symlink_name(link_tree):
    scope = _scope(link_tree, "-F", r".*excluded\.yml")

    yielded_names = {path.name for path in scope}
    assert "excluded_link.yml" not in yielded_names


def test_include_glob_semantics_kept(link_tree):
    root = link_tree["root"]
    scope = _scope(link_tree, "-f", "**/deep.yml")

    assert scope == [(root / "real" / "sub" / "deep.yml").resolve()]


def test_nonexistent_root_produces_no_pairs(link_tree):
    args = parse_args([(link_tree["base"] / "missing").as_posix()])
    config = load_config(args)

    assert list(load_scope(args, config)) == []


def test_symlinked_scan_root_keeps_real_root_boundary(link_tree):
    args = parse_args([link_tree["root_link"].as_posix()])
    config = load_config(args)
    scope = [path.resolve() for path in load_scope(args, config)]

    root = link_tree["root"].resolve()
    assert scope
    assert all(root in path.parents for path in scope)
    assert all(link_tree["outside"].resolve() not in path.parents for path in scope)


def test_explicit_single_file_scan_kept(link_tree):
    target = link_tree["outside"] / "secret.yml"
    args = parse_args([target.as_posix()])
    config = load_config(args)
    scope = list(load_scope(args, config))

    assert len(scope) == 1
    assert scope[0].resolve() == target.resolve()


def test_explicit_broken_file_scan_produces_no_pairs(link_tree):
    args = parse_args([(link_tree["root"] / "broken").as_posix()])
    config = load_config(args)

    assert list(load_scope(args, config)) == []
