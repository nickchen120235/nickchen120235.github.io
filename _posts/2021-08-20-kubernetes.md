---
layout: post
title: Kubernetes學習筆記
tags: [notes]
---

今天在公司<s>薪偷</s>找點東西學（<s>Web題那麼無聊我才不要繼續研究</s>）

內容基本上都是來自[https://kubernetes.io/](https://kubernetes.io/)

## 介紹
> Kubernetes, also known as K8s, is an open-source system for automating deployment, scaling, and management of containerized applications.
> 
> It groups containers that make up an application into logical units for easy management and discovery.

Kubernetes本身並不做「容器化」，而是透過自己的一些方法更好的去管理「容器化」的應用程式，「容器化」本身還是交給[Docker](https://www.docker.com/)這種容器化引擎下去做

「分組」的部份，Docker有一個CLI工具[docker-compose](https://github.com/docker/compose)也可以達到一次管理多個容器的功能，不過僅限於本地的機器。
對於跨機器管理，Docker有一個[Swarm](https://docs.docker.com/engine/swarm/)模式，不過Kubernetes提供更強大的功能，也因此被廣泛使用

## 概念
### Cluster
![cluster]({{"/assets/img/posts/2021-08-20-kubernetes/cluster.jpg" | relative_url}}){:style="max-height: 400px; display: block; margin: auto"}

> A set of worker machines, called nodes, that run containerized applications. Every cluster has at least one worker node.

簡單來說就是一堆跑docker的機器

Kubernetes中對於資源的管理是以cluster為單位，也就是在deploy的時候不是放到特定一台機器上，而是丟到整個cluster裡面，由cluster內部進行管理與佈署

一個cluster擁有兩種不同資源（機器），兩者之間用Kubernetes API溝通
- Control Plane：負責管理cluster大小事，包含應用程式佈署、監控、維護等
- Node：進行容器化操作的機器，可以是實體或虛擬機器

### Node
![node]({{"/assets/img/posts/2021-08-20-kubernetes/node.jpg" | relative_url}}){:style="max-height: 400px; display: block; margin: auto"}

> A Node is a worker machine in Kubernetes and may be either a virtual or a physical machine, depending on the cluster. Each Node is managed by the control plane. 

實際佈署應用程式的地方，control plane會根據各個node的負載狀況分配不同數量的工作給各個節點，就像多CPU的scheduling那樣

每個node至少會運行以下兩個東西
- kubelet，負責與control plane之間的通訊
- 負責容器化操作的runtime，像是docker

### Pod
![pods]({{"/assets/img/posts/2021-08-20-kubernetes/pods.jpg" | relative_url}}){:style="max-height: 400px; display: block; margin: auto"}

> A Pod models an application-specific "logical host" and can contain different application containers which are relatively tightly coupled.

Pod是Kubernetes的最小單位，包含數個容器以及共享的資源（volume、IP等），deploy的時候會根據描述建立一個pod

一個node可以含有多個pod，每個pod有一個IP，被pod內的容器共享

### Deployment
![deployment]({{"/assets/img/posts/2021-08-20-kubernetes/deployment.jpg" | relative_url}}){:style="max-height: 400px; display: block; margin: auto"}

Deployment是一個告訴kubernetes如何建立與更新一個應用程式實例的過程

下達指令後，由control plane進行排程，決定要在哪一個node上建立pod

應用實例跑起來後，control plane會持續監測實例們的狀況，一旦其中一個node死掉時，controller會嘗試在另一個node上建立實例，降低down time

### Service
![service]({{"/assets/img/posts/2021-08-20-kubernetes/service.jpg" | relative_url}}){:style="max-height: 400px; display: block; margin: auto"}

> A Kubernetes Service is an abstraction layer which defines a logical set of Pods and enables external traffic exposure, load balancing and service discovery for those Pods.

Service將一堆pods（例如透過Replica建立的相同功能pod）抽象為一個對外的服務，並處理內部路由的問題，如節點死掉切換等

Service有四種模式
- ClusterIP：預設模式，該服務只能在同一個cluster內使用
- NodePort：透過NAT將服務expose到cluster以外
- LoadBalancer：透過固定的對外IP將服務expose到cluster以外
- ExternalName：透過域名形式將服務expose到cluster以外

如圖所示，對每個pod標上標籤，具有相同標籤的pods在建立服務時會在同一組，對外存取點是`1.1.1.1`，當從外面存取`A`時，Service會依照設定好的邏輯去路由流量，假設主存取點死掉時，Service就會去尋找其他具有`A`標籤的pod並把流量路由過去