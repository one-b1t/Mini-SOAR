"""Helper statis reusable: cari nama yang dibaca tapi tidak pernah terikat.

Dipakai untuk menangkap kelas bug seperti BUG 4 (refactor auth_guard menghapus
blok yang men-set `user = update.effective_user`, tapi 17 handler masih
membacanya → NameError di happy path) tanpa perlu menulis satu test runtime
per handler.

Implementasinya memakai `symtable` dari stdlib, bukan walk AST manual.
symtable adalah resolver scope yang sama dengan yang dipakai compiler CPython,
jadi ia sudah benar untuk comprehension, closure, walrus, global/nonlocal,
except-as, dan argumen kwonly/posonly — hal-hal yang gampang salah kalau
scope-nya kita hitung sendiri dari AST.
"""

import builtins
import symtable


def _module_bindings(table):
    """Semua nama yang terikat di level modul (assign, def, class, import)."""
    return {sym.get_name() for sym in table.get_symbols() if sym.is_assigned() or sym.is_imported()}


def _walk(table, path=()):
    """Yield (qualified_name, child_table) untuk tiap function scope."""
    for child in table.get_children():
        name = path + (child.get_name(),)
        if child.get_type() == "function":
            yield name, child
        yield from _walk(child, name)


def undefined_names(source, filename="<source>", ignore=()):
    """Kembalikan daftar 'fungsi:baris:nama' untuk nama global yang tak pernah ada.

    Sebuah nama dilaporkan kalau, di dalam sebuah function scope, ia dibaca dan
    diresolusi ke global, padahal tidak ada di binding level modul maupun di
    builtins. Itu persis kondisi yang meledak jadi NameError saat runtime.

    `ignore` untuk nama yang memang disuntikkan dari luar (mis. fixture,
    variabel yang dibuat exec/globals()) — kosongkan kalau tidak perlu.
    """
    top = symtable.symtable(source, filename, "exec")
    known = _module_bindings(top) | set(dir(builtins)) | set(ignore)

    found = []
    for qual, table in _walk(top):
        for sym in table.get_symbols():
            name = sym.get_name()
            if name in known:
                continue
            if not sym.is_referenced():
                continue
            # is_global() True = compiler memutuskan nama ini dicari di global scope.
            # Kalau ia juga tidak terikat di mana-mana, runtime akan NameError.
            if sym.is_global() and not sym.is_assigned():
                found.append(f"{'.'.join(qual)}:{table.get_lineno()}:{name}")
    return sorted(found)


def undefined_names_in_module(module, ignore=()):
    """Versi praktis: terima objek module, baca file sumbernya."""
    import inspect

    path = inspect.getsourcefile(module)
    with open(path, encoding="utf-8") as fh:
        return undefined_names(fh.read(), filename=path, ignore=ignore)
