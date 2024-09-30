package main

import (
	"database/sql"
	"fmt"
	"github.com/casbin/casbin/v2"
	xormadapter "github.com/casbin/xorm-adapter/v3"
	_ "github.com/lib/pq"
	"log"
)

func main() {
	ClearPolicies()

	casbin, err := NewCasbinEnforcer()
	if err != nil {
		panic(fmt.Sprintf("Failed to create casbin enforcer: %s", err))
	}

	_, err = casbin.AddPolicy("general", "datacenter", "nuke")
	if err != nil {
		panic(fmt.Sprintf("Failed to add policy: %s", err))
	}

	_, err = casbin.AddPolicy("general", "datacenter", "disarm")
	if err != nil {
		panic(fmt.Sprintf("Failed to add policy: %s", err))
	}

	_, err = casbin.AddPolicy("cleaner", "datacenter", "radiation:cleaning")
	if err != nil {
		panic(fmt.Sprintf("Failed to add policy: %s", err))
	}

	_, err = casbin.AddPolicy("garbage", "datacenter", "trashcan:empty")
	if err != nil {
		panic(fmt.Sprintf("Failed to add policy: %s", err))
	}

	//Add Garbage to Cleaner
	_, err = casbin.AddGroupingPolicy("cleaner", "garbage")
	if err != nil {
		panic(fmt.Sprintf("Failed to add policy: %s", err))
	}

	_, err = casbin.AddGroupingPolicy("admin", "garbage")
	if err != nil {
		panic(fmt.Sprintf("Failed to add policy: %s", err))
	}

	//Add General
	_, err = casbin.AddRoleForUser("Alice", "general")
	if err != nil {
		panic(fmt.Sprintf("Failed to add admin role: %s", err))
	}

	//Add Cleaner
	_, err = casbin.AddRoleForUser("Bob", "cleaner")
	if err != nil {
		panic(fmt.Sprintf("Failed to add admin role: %s", err))
	}

	//Check General permissions
	fmt.Println("\nAlice Permissions")
	nukePermission, err := CheckPermission("Alice", "datacenter", "nuke")
	if err != nil {
		panic(fmt.Sprintf("Failed to check permission: %s", err))
	} else {
		fmt.Printf("Nuke Permission: %t\n", *nukePermission)
	}

	disarmPermission, err := CheckPermission("Alice", "datacenter", "disarm")
	if err != nil {
		panic(fmt.Sprintf("Failed to check permission: %s", err))
	} else {
		fmt.Printf("Disarm Permission: %t\n", *disarmPermission)
	}

	cleanerPermission, err := CheckPermission("Alice", "datacenter", "radiation:cleaning")
	if err != nil {
		panic(fmt.Sprintf("Failed to check permission: %s", err))
	} else {
		fmt.Printf("Cleaner Permission: %t\n", *cleanerPermission)
	}

	trashcanPermission, err := CheckPermission("Alice", "datacenter", "trashcan:empty")
	if err != nil {
		panic(fmt.Sprintf("Failed to check permission: %s", err))
	} else {
		fmt.Printf("Trashcan Permission: %t\n", *trashcanPermission)
	}

	//Check Cleaner permissions
	fmt.Println("\nBob Permissions")

	nukePermission, err = CheckPermission("Bob", "datacenter", "nuke")
	if err != nil {
		panic(fmt.Sprintf("Failed to check permission: %s", err))
	} else {
		fmt.Printf("Nuke Permission: %t\n", *nukePermission)
	}

	disarmPermission, err = CheckPermission("Bob", "datacenter", "disarm")
	if err != nil {
		panic(fmt.Sprintf("Failed to check permission: %s", err))
	} else {
		fmt.Printf("Disarm Permission: %t\n", *disarmPermission)
	}

	cleanerPermission, err = CheckPermission("Bob", "datacenter", "radiation:cleaning")
	if err != nil {
		panic(fmt.Sprintf("Failed to check permission: %s", err))
	} else {
		fmt.Printf("Cleaner Permission: %t\n", *cleanerPermission)
	}

	trashcanPermission, err = CheckPermission("Bob", "datacenter", "trashcan:empty")
	if err != nil {
		panic(fmt.Sprintf("Failed to check permission: %s", err))
	} else {
		fmt.Printf("Trashcan Permission: %t\n", *trashcanPermission)
	}

}

func CreateWorklogPolicies() {
	e, err := NewCasbinEnforcer()
	if err != nil {
		panic(fmt.Sprintf("Failed to create casbin enforcer: %s", err))
	}

	//Worklog Policies
	var policies = [][]string{
		{"workLog:read_write", "workLog:read"},
		{"workLog:read_write", "workLog:write"},
		{"admin", "workLog:read_write"},
	}

	_, err = e.AddPolicies(policies)
	if err != nil {
		panic(fmt.Sprintf("Failed to add policies: %s", err))
	}
}

func GiveAdminWorkLogPermissions() {
	e, err := NewCasbinEnforcer()
	if err != nil {
		panic(fmt.Sprintf("Failed to create casbin enforcer: %s", err))
	}

	_, err = e.AddRoleForUser("Alice", "admin")
	if err != nil {
		panic(fmt.Sprintf("Failed to add admin role: %s", err))
	}
}

func AddWorkLog(employeeId string, workLogId string) error {
	e, err := NewCasbinEnforcer()
	if err != nil {
		return err
	}

	_, err = e.AddPolicy(workLogId, "workLog:read_write")
	if err != nil {
		return err
	}

	if _, err := e.AddPolicy(employeeId, workLogId); err != nil {
		return err
	}

	if err = e.SavePolicy(); err != nil {
		panic(fmt.Sprintf("Failed to save policy: %s", err))
	}

	return nil
}

func CheckPermission(sub string, obj string, act string) (*bool, error) {
	e, err := NewCasbinEnforcer()
	if err != nil {
		return nil, err
	}

	// Check the permission.
	enforcer, err := e.Enforce(sub, obj, act)
	if err != nil {
		panic(fmt.Sprintf("Failed to enforce policy: %s", err))
	}

	return &enforcer, nil
}

func AddAdminRole(sub string) error {
	e, err := NewCasbinEnforcer()
	if err != nil {
		return err
	}

	if _, err := e.AddRoleForUser(sub, "admin"); err != nil {
		return err
	}

	if err = e.SavePolicy(); err != nil {
		panic(fmt.Sprintf("Failed to save policy: %s", err))
	}

	return nil
}

func AddRolePolicy(role string, obj string, act string) error {
	e, err := NewCasbinEnforcer()
	if err != nil {
		return err
	}

	if _, err := e.AddPolicy(role, obj, act); err != nil {
		return err
	}

	if err = e.SavePolicy(); err != nil {
		panic(fmt.Sprintf("Failed to save policy: %s", err))
	}

	return nil
}

func AddPolicy(sub string, obj string) error {
	e, err := NewCasbinEnforcer()
	if err != nil {
		return err
	}

	if _, err := e.AddPolicy(sub, obj); err != nil {
		return err
	}

	if err = e.SavePolicy(); err != nil {
		panic(fmt.Sprintf("Failed to save policy: %s", err))
	}

	return nil
}

func ClearPolicies() {
	// Define connection string
	connStr := "user=ap_admin password=mysecretpassword dbname=casbin host=localhost sslmode=disable"

	// Open a database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	// Delete the table
	_, err = db.Exec("DROP TABLE IF EXISTS public.casbin_role")
	if err != nil {
		log.Fatalf("Error deleting table: %v", err)
	}

	fmt.Println("Table public.casbin_role deleted successfully.")
}

func NewCasbinEnforcer() (*casbin.Enforcer, error) {
	a, err := xormadapter.NewAdapter("postgres", "user=ap_admin password=mysecretpassword host=127.0.0.1 port=5432 sslmode=disable") // Your driver and data source.
	if err != nil {
		panic(err)
	}

	e, err := casbin.NewEnforcer("Policies/company.model.conf", a)
	if err != nil {
		panic(err)
	}

	if err = e.LoadPolicy(); err != nil {
		panic(fmt.Sprintf("Failed to load policy: %s", err))
	}

	return e, nil
}
