# Ansible Kubernetes
Manage Kubernetes.

# Authorize Cortex XSOAR for Kubernetes

This integration supports API Token, and Username/Password authentication. It is recommended to use API tokens.

To create a service account with API token use the following `kubectl` commands.

1. Create a service account
```
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: xsoar
  namespace: kube-system
EOF
```

2. Grant the service account an appropriate role. Refer to [Kubernetes RBAC docs](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) if granting more fine grain or scoped access.
```
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: xsoar-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: xsoar
  namespace: kube-system
EOF
```
3. Retrieve the token object name created into a env var called TOKEN
```
TOKENNAME=`kubectl -n kube-system get serviceaccount/xsoar -o jsonpath='{.secrets[0].name}'`
```
4. Output the API token value
```
kubectl -n kube-system get secret $TOKENNAME -o jsonpath='{.data.token}' | base64 -d
```

## Testing

This integration does not support testing from the integration management screen. Instead it is recommended to use the `!k8s-info` command querying a object `kind` allowed by the RBAC assigned. For example `!k8s-info kind="svc"`