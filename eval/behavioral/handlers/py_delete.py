import shutil


def delete_tree(path: str) -> str:
    shutil.rmtree(path)
    return path
