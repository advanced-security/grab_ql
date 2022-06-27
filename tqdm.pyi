from typing import Any, ContextManager, TypeVar

_T = TypeVar("_T")
def tqdm(**kwargs: Any) -> ContextManager[_T]: ...
