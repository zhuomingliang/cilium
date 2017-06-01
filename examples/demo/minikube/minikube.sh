#!/usr/bin/env bash

. $(dirname ${BASH_SOURCE})/../../../contrib/shell/util.sh

PWD=$(dirname ${BASH_SOURCE})

function cleanup {
	minikube delete
}

trap cleanup EXIT
cleanup

desc_rate "This demo shows how to deploy Cilium on minikube and apply L7 policies"
run ""

desc_rate "Create a minikube based Kubernetes cluster"
run "minikube start --network-plugin=cni --iso-url https://github.com/cilium/minikube-iso/raw/master/minikube.iso"
run "kubectl get cs"

desc_rate "Deploy Cilium using a DaemonSet"
run "kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/minikube/cilium-ds.yaml"

desc_rate "Check status of DaemonSet and wait until Cilium is deployed"
run "kubectl get ds --namespace kube-system"
run "kubectl get ds --namespace kube-system"

desc_rate "Deploy the demo app"
run "cat diagram"
run "kubectl create -f https://raw.githubusercontent.com/cilium/cilium/master/examples/minikube/demo.yaml"

desc_rate "Check progress of deployment"
run "kubectl get pods,svc"
run "kubectl get pods,svc"

desc "/public and /private are both available"
APP2_POD=$(kubectl get pods -l id=app2 -o jsonpath='{.items[0].metadata.name}')
run "APP2_POD=$(kubectl get pods -l id=app2 -o jsonpath='{.items[0].metadata.name}')"
SVC_IP=$(kubectl get svc app1-service -o jsonpath='{.spec.clusterIP}')
run "SVC_IP=$(kubectl get svc app1-service -o jsonpath='{.spec.clusterIP}')"

desc "Access app1-service/public"
kubectl exec $APP2_POD -- curl -s http://${SVC_IP}/public

desc "Access app1-service/private"
kubectl exec $APP2_POD -- curl -s http://${SVC_IP}/private

desc_rate "Import L7 policy"
run "cat l7_policy.yaml"
run "kubectl create -f l7_policy.yaml"


desc "Access app1-service/public again"
kubectl exec $APP2_POD -- curl -s http://${SVC_IP}/public

desc "Access app1-service/private again"
kubectl exec $APP2_POD -- curl -s http://${SVC_IP}/private

desc "Cleaning up..."
