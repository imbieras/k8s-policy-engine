package db

import (
	"context"
	"fmt"
	"policy-engine/pkg/models"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type KubernetesClient struct {
	clientset kubernetes.Interface
	namespace string
}

func NewKubernetesClient(namespace string) (*KubernetesClient, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	return &KubernetesClient{
		clientset: clientset,
		namespace: namespace,
	}, nil
}

func (kc *KubernetesClient) CreateRoleBinding(ctx context.Context, request *models.Request) error {
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      request.ID,
			Namespace: kc.namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     request.Role,
		},
		Subjects: []rbacv1.Subject{
			{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "User",
				Name:     request.UserIdentity,
			},
		},
	}

	_, err := kc.clientset.RbacV1().RoleBindings(kc.namespace).Create(ctx, roleBinding, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create rolebinding: %w", err)
	}

	return nil
}

func (kc *KubernetesClient) DeleteRoleBinding(ctx context.Context, name string) error {
	err := kc.clientset.RbacV1().RoleBindings(kc.namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete rolebinding: %w", err)
	}
	return nil
}
