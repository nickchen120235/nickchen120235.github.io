---
layout: post
title: URI Normalization
tags: [Notes, web]
---

總之今天在打 [Portswigger Web Security Academy 的 Lab](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-client-side-redirect) 的時候，
在官方 solution 看到一個怎麼想也想不到的東西

> Try injecting a path traversal sequence so that the dynamically constructed redirect URL will point to your account page:
> ```
> /post/comment/confirmation?postId=1/../../my-account
> ```

結果我把這個 `../` 的東西拿去別的網站用也可以，
而且這個 traverse 的是由 Firefox 完成的

一去查才發現有這個東西：[URI Normalization](https://en.wikipedia.org/wiki/URI_normalization)

其中有一項是 Remove dot-segments，
這個動作定義於 [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.4)，
簡單來說就是你可以用類似 terminal 中 `cd ../` 的方式去打一個 URI，
然後根據這條規則，那個 URI 就會指向不同的資源

留著做打 web 題的參考
