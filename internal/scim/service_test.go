package scim

import (
	"context"
	"testing"
	"time"

	"github.com/dhawalhost/wardseal/internal/directory"
)

type fakeDirectoryService struct {
	createUserID string
	lastCreate   directory.User
	lastLimit    int
	lastOffset   int
	lastUpdateID string
	lastUpdate   directory.User

	users       []directory.User
	totalUsers  int
	groups      []directory.Group
	totalGroups int

	currentUser directory.User
}

func (f *fakeDirectoryService) HealthCheck(context.Context) (bool, error) { return true, nil }

func (f *fakeDirectoryService) CreateUser(_ context.Context, _ string, user directory.User) (string, error) {
	f.lastCreate = user
	if f.createUserID == "" {
		return "user-1", nil
	}
	return f.createUserID, nil
}

func (f *fakeDirectoryService) GetUserByID(_ context.Context, _ string, _ string) (directory.User, error) {
	if f.currentUser.ID == "" {
		f.currentUser = directory.User{ID: "user-1", Email: "user@wardseal.com", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	}
	return f.currentUser, nil
}

func (f *fakeDirectoryService) GetUserByEmail(context.Context, string, string) (directory.User, error) {
	return directory.User{}, nil
}

func (f *fakeDirectoryService) ListUsers(_ context.Context, _ string, limit, offset int) ([]directory.User, int, error) {
	f.lastLimit = limit
	f.lastOffset = offset
	if f.users == nil {
		f.users = []directory.User{{ID: "u1", Email: "u1@wardseal.com", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}}
		f.totalUsers = 1
	}
	return f.users, f.totalUsers, nil
}

func (f *fakeDirectoryService) UpdateUser(_ context.Context, _ string, id string, user directory.User) error {
	f.lastUpdateID = id
	f.lastUpdate = user
	return nil
}

func (f *fakeDirectoryService) DeleteUser(context.Context, string, string) error { return nil }

func (f *fakeDirectoryService) CreateGroup(context.Context, string, directory.Group) (string, error) {
	return "group-1", nil
}

func (f *fakeDirectoryService) GetGroupByID(context.Context, string, string) (directory.Group, error) {
	return directory.Group{ID: "group-1", Name: "Engineering", CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
}

func (f *fakeDirectoryService) ListGroups(_ context.Context, _ string, limit, offset int) ([]directory.Group, int, error) {
	f.lastLimit = limit
	f.lastOffset = offset
	if f.groups == nil {
		f.groups = []directory.Group{{ID: "g1", Name: "Engineering", CreatedAt: time.Now(), UpdatedAt: time.Now()}}
		f.totalGroups = 1
	}
	return f.groups, f.totalGroups, nil
}

func (f *fakeDirectoryService) UpdateGroup(context.Context, string, string, directory.Group) error {
	return nil
}

func (f *fakeDirectoryService) DeleteGroup(context.Context, string, string) error { return nil }
func (f *fakeDirectoryService) AddUserToGroup(context.Context, string, string, string) error {
	return nil
}
func (f *fakeDirectoryService) RemoveUserFromGroup(context.Context, string, string, string) error {
	return nil
}
func (f *fakeDirectoryService) VerifyCredentials(context.Context, string, string, string) (directory.User, error) {
	return directory.User{}, nil
}
func (f *fakeDirectoryService) GetTenantByEmail(context.Context, string) (string, error) {
	return "", nil
}
func (f *fakeDirectoryService) CreateTenant(context.Context, string, string, string, string) error {
	return nil
}

func TestCreateUserPrefersPrimaryEmail(t *testing.T) {
	fake := &fakeDirectoryService{createUserID: "user-123"}
	svc := NewService(fake)

	req := User{
		Schemas:  []string{UserSchema},
		UserName: "fallback@wardseal.com",
		Active:   true,
		Emails: []Email{
			{Value: "secondary@wardseal.com", Primary: false},
			{Value: "primary@wardseal.com", Primary: true},
		},
	}

	created, err := svc.CreateUser(context.Background(), "tenant-1", req)
	if err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	if fake.lastCreate.Email != "primary@wardseal.com" {
		t.Fatalf("expected primary email to be used, got %s", fake.lastCreate.Email)
	}
	if created.ID != "user-123" {
		t.Fatalf("expected created id user-123, got %s", created.ID)
	}
}

func TestCreateUserUsesProvidedPassword(t *testing.T) {
	fake := &fakeDirectoryService{createUserID: "user-123"}
	svc := NewService(fake)

	req := User{
		Schemas:  []string{UserSchema},
		UserName: "user@wardseal.com",
		Password: "MyStrongP@ssword123",
		Active:   true,
	}

	_, err := svc.CreateUser(context.Background(), "tenant-1", req)
	if err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	if fake.lastCreate.Password != "MyStrongP@ssword123" {
		t.Fatalf("expected provided password to be used")
	}
}

func TestCreateUserRejectsShortPassword(t *testing.T) {
	fake := &fakeDirectoryService{createUserID: "user-123"}
	svc := NewService(fake)

	req := User{
		Schemas:  []string{UserSchema},
		UserName: "user@wardseal.com",
		Password: "short",
		Active:   true,
	}

	_, err := svc.CreateUser(context.Background(), "tenant-1", req)
	if err == nil {
		t.Fatalf("expected validation error for short password")
	}
}

func TestCreateUserGeneratesNonStaticPasswordWhenMissing(t *testing.T) {
	fake := &fakeDirectoryService{createUserID: "user-123"}
	svc := NewService(fake)

	req := User{
		Schemas:  []string{UserSchema},
		UserName: "user@wardseal.com",
		Active:   true,
	}

	_, err := svc.CreateUser(context.Background(), "tenant-1", req)
	if err != nil {
		t.Fatalf("CreateUser returned error: %v", err)
	}

	if fake.lastCreate.Password == "" {
		t.Fatalf("expected generated password to be non-empty")
	}
	if fake.lastCreate.Password == "ChangeMe123!" {
		t.Fatalf("expected non-static generated password")
	}
}

func TestListUsersAppliesScimPaginationDefaults(t *testing.T) {
	fake := &fakeDirectoryService{
		users:      []directory.User{{ID: "u1", Email: "u1@wardseal.com", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}},
		totalUsers: 42,
	}
	svc := NewService(fake)

	resp, err := svc.ListUsers(context.Background(), "tenant-1", "", 0, 500)
	if err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}

	if fake.lastLimit != 100 {
		t.Fatalf("expected normalized limit=100, got %d", fake.lastLimit)
	}
	if fake.lastOffset != 0 {
		t.Fatalf("expected normalized offset=0, got %d", fake.lastOffset)
	}
	if resp.StartIndex != 1 {
		t.Fatalf("expected StartIndex=1, got %d", resp.StartIndex)
	}
	if resp.TotalResults != 42 {
		t.Fatalf("expected TotalResults=42, got %d", resp.TotalResults)
	}
	if len(resp.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resp.Resources))
	}
}

func TestPatchUserReplaceActiveAndUserName(t *testing.T) {
	fake := &fakeDirectoryService{
		currentUser: directory.User{ID: "u1", Email: "old@wardseal.com", Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}
	svc := NewService(fake)

	ops := []PatchOperation{
		{Op: "replace", Path: "active", Value: false},
		{Op: "replace", Path: "userName", Value: "new@wardseal.com"},
	}

	_, err := svc.PatchUser(context.Background(), "tenant-1", "u1", ops)
	if err != nil {
		t.Fatalf("PatchUser returned error: %v", err)
	}

	if fake.lastUpdateID != "u1" {
		t.Fatalf("expected update id u1, got %s", fake.lastUpdateID)
	}
	if fake.lastUpdate.Email != "new@wardseal.com" {
		t.Fatalf("expected updated email new@wardseal.com, got %s", fake.lastUpdate.Email)
	}
	if fake.lastUpdate.Status != "inactive" {
		t.Fatalf("expected status inactive, got %s", fake.lastUpdate.Status)
	}
}

func TestListGroupsAppliesPagination(t *testing.T) {
	fake := &fakeDirectoryService{
		groups:      []directory.Group{{ID: "g1", Name: "Engineering", CreatedAt: time.Now(), UpdatedAt: time.Now()}},
		totalGroups: 7,
	}
	svc := NewService(fake)

	resp, err := svc.ListGroups(context.Background(), "tenant-1", 2, 1)
	if err != nil {
		t.Fatalf("ListGroups returned error: %v", err)
	}

	if fake.lastLimit != 1 {
		t.Fatalf("expected limit=1, got %d", fake.lastLimit)
	}
	if fake.lastOffset != 1 {
		t.Fatalf("expected offset=1, got %d", fake.lastOffset)
	}
	if resp.StartIndex != 2 {
		t.Fatalf("expected StartIndex=2, got %d", resp.StartIndex)
	}
	if resp.TotalResults != 7 {
		t.Fatalf("expected TotalResults=7, got %d", resp.TotalResults)
	}
	if len(resp.Resources) != 1 {
		t.Fatalf("expected 1 group resource, got %d", len(resp.Resources))
	}
}
