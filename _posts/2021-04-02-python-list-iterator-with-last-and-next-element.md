---
layout: post
title: Python List Iterator with Last and Next Element
tags: [Notes]
---
```py
from __future__ import annotations
from itertools import tee, chain
from typing import TypeVar, Tuple
from collections.abc import Iterator

def prev_curr_next(iterable: list[T]) -> Iterator[Tuple[None or T, T, None or T]]:
  a, b, c = tee(chain([None], iterable, [None]), 3)
  next(b, None)
  next(c, None)
  next(c, None)
  return zip(a, b, c)

arr = [1, 2, 3, 4, 5]
for i in prev_curr_next(arr): print(i)
"""output
(None, 1, 2)
(1, 2, 3)
(2, 3, 4)
(3, 4, 5)
(4, 5, None)
"""
```