---
layout: post
title: Google Cloud Service Account 權限筆記
tags: [Notes]
---
[這篇文章](https://nickchen120235.github.io/2022/08/02/google-cloud-function-github-cicd.html)的後續，目前總共試了三個Google Cloud 服務

- Google Cloud Function [對應的GitHub Repo (with TypeScript)](https://github.com/nickchen120235/google-cloud-cicd-ts)
- Google Firestore [對應的GitHub Repo (with TypeScript)](https://github.com/nickchen120235/gcf-firestore-ts)
- Google Cloud Storage [對應的GitHub Repo (with Python)](https://github.com/nickchen120235/github-cicd-python-gcs)

一般來說使用者權限要盡量小（最小權限原則），所以現在在嘗試自訂角色去設權限，只要能夠上傳/更新就可以

目前試出來的權限如下
- Google Cloud Function：能夠透過CI/CD佈署API
  - default `roles/cloudfunctions.Developer`
- Google Firestore：能夠正常進行CRUD
  - `datastore.databases.get`
  - `datastore.databases.getMetadata`
  - `datastore.entities.allocateIds`
  - `datastore.entities.create`
  - `datastore.entities.delete`
  - `datastore.entities.get`
  - `datastore.entities.list`
  - `datastore.entities.update`
  - `datastore.indexes.list`
- Google Cloud Storage：能夠透過CI/CD上傳/更新物件
  - `storage.objects.create`
  - `storage.objects.delete`
  - `storage.objects.list`
  - `storage.objects.update`