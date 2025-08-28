import os
import idaapi
import idc
from dataclasses import dataclass
from typing import List

# todo: track script renames
# pip install gitpython


@dataclass
class Script:
    name: str
    lang: str
    content: str
    ext: str


def slugify(s: str):
    import re
    import unicodedata

    normalized = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()
    normalized = re.sub(r"[^\w\s-]", "", normalized).strip().lower()
    return re.sub(r"[-\s]+", "_", normalized)


# until find_extlang_by_name gets exposed in IDAPython, here is this thing:
def language_to_ext(language: bytes | str) -> str:
    match language:
        case "Python" | b"Python":
            return "py"
        case "IDC" | b"IDC":
            return "idc"
        case _:
            return "txt"


def get_scripts() -> List[Script]:
    scripts = []
    snippets_netnode = idaapi.netnode("$ scriptsnippets")
    for i in range(snippets_netnode.altfirst(), snippets_netnode.altlast() + 1):
        n = snippets_netnode.altval(i)
        if n == 0:
            break
        s = idaapi.netnode(n - 1)
        nm = s.supval(0).strip(b"\x00")
        sc = s.supval(1).strip(b"\x00")
        text = s.getblob(0, "X")
        if not text:
            text = b""
        text = text.strip(b"\x00")

        scripts.append(
            Script(nm.decode(), sc.decode(), text.decode(), language_to_ext(sc))
        )
    return scripts


def submit_to_repo(path, commit_name):
    from git import Repo

    repo = Repo(path)
    repo.index.add(["*repository*"])
    dif = repo.index.diff("HEAD")
    if len(dif) > 0:
        repo.index.commit(commit_name)
    return len(dif)


def export_all(path):
    scripts = get_scripts()
    if len(scripts) == 0:
        print("nothing to export")
        return 0

    repo_path = os.path.join(path, "repository")
    project_path = os.path.join(repo_path, idaapi.retrieve_input_file_sha256().hex())

    if not os.path.isdir(project_path):
        os.mkdir(project_path)

    for script in scripts:
        fname = f"{slugify(script.name)}.{script.ext}"
        full_path = os.path.join(project_path, fname)

        if os.path.exists(full_path):
            with open(full_path, "r") as f:
                old = f.read()
            if old == script.content:
                continue
        with open(full_path, "w") as f:
            f.write(script.content)

    commit_name = f"idb: {idc.get_idb_path()}\nsha256: {idaapi.retrieve_input_file_sha256().hex()}"
    return submit_to_repo(path, commit_name)


def find_existing_script_directory():
    paths = [os.path.expanduser("~/Documents/ida scripts")]
    for path in paths:
        if os.path.exists(path):
            return path


def commit_files_to_git():
    path = find_existing_script_directory()
    if not path:
        print("No script directory found")
        return
    changed_count = export_all(path)
    print(f"commited {changed_count} file{'s' if changed_count != 1 else ''}")


class export_scripts_handler_t(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        commit_files_to_git()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class DatabaseClosedHook(idaapi.IDP_Hooks):
    def __init__(self):
        super().__init__()

    def closebase(self):
        # Handle database closed event
        pass


class ExportsPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE
    comment = "exports all scripts to git repository and commits them"
    help = "TODO"
    wanted_name = "export_scripts"
    wanted_hotkey = ""
    actname = "milankovo:export_scripts"

    def init(self):
        addon = idaapi.addon_info_t()
        addon.id = "milanek.scripts_export"
        addon.name = "export scripts to git"
        addon.producer = "Milanek"
        addon.url = "https://github.com/milankovo/ida_export_scripts"
        addon.version = "9.0"
        idaapi.register_addon(addon)
        self.action_desc = idaapi.action_desc_t(
            self.actname, "exports all scripts to git", export_scripts_handler_t()
        )
        idaapi.register_action(self.action_desc)
        self.db_hook = DatabaseClosedHook()
        self.db_hook.hook()
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.unregister_action(self.actname)
        if self.db_hook:
            self.db_hook.unhook()
            del self.db_hook

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return ExportsPlugin()
