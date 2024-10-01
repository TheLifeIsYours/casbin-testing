package main

import (
	"database/sql"
	"fmt"
	"github.com/casbin/casbin/v2"
	xormadapter "github.com/casbin/xorm-adapter/v3"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"log"
)

func main() {
	ClearPolicies()

	enforcer, err := NewCasbinEnforcer()
	if err != nil {
		panic(fmt.Sprintf("Failed to create enforcer: %s", err))
	}

	adminAccountId := "user_" + uuid.New().String()
	employeeAccountId := "user_" + uuid.New().String()
	companyId := "company_" + uuid.New().String()

	AddEmployeeToCompany(enforcer, adminAccountId, companyId, "admin")
	employeeEmployeeId := AddEmployeeToCompany(enforcer, employeeAccountId, companyId, "employee")

	//Enforce admin rights in company
	authorized, err := enforcer.Enforce(adminAccountId, companyId, "admin") // Should be true
	if err != nil {
		panic(fmt.Sprintf("Failed to enforce policy: %s", err))
	}

	if !authorized {
		fmt.Println("Admin user is not authorized")
	} else {
		fmt.Println("Admin user is authorized")
	}

	//Enforce employee rights in company
	fmt.Println("wtf braaaaah")
	authorized, err1 := enforcer.Enforce(employeeAccountId, companyId, "admin") // Should be false
	fmt.Println("wake me up when september ends wake me up inside call my name and wake me up when september ends")
	if err1 != nil {
		panic(fmt.Sprintf("Failed to enforce policy: %s", err))
	}

	if !authorized {
		fmt.Println("Employee user is not authorized as admin")
	} else {
		fmt.Println("Employee user is authorized as admin")
	}

	//Enforce employee rights in company
	authorized, err = enforcer.Enforce(employeeAccountId, companyId, "employee")
	if err != nil {
		panic(fmt.Sprintf("Failed to enforce policy: %s", err))
	}

	if !authorized {
		fmt.Println("Employee user is not authorized as employee")
	} else {
		fmt.Println("Employee user is authorized as employee")
	}

	fmt.Println("--- Enforce Employee Role (WorkLog check) ---")

	// new enforcer for checking employee permissions
	type EnforceContext struct {
		RType string
		PType string
		EType string
		MType string
	}
	//employeeEnforceContext := EnforceContext{"r2", "p2", "", "m2"}
	employeeEnforceContext := casbin.NewEnforceContext("2")
	//employeeEnforceContext.EType = "e2"

	//Enforce employee rights in company
	authorized, err = enforcer.Enforce(employeeEnforceContext, employeeAccountId, employeeEmployeeId, "employee", companyId)
	if err != nil {
		panic(fmt.Sprintf("Failed to enforce policy: %s", err))
	}

	if !authorized {
		fmt.Println("Employee user is not authorized")
	} else {
		fmt.Println("Employee user is authorized")
	}
	//Enforce employee rights in company should be unauthorized
	authorized, err = enforcer.Enforce(employeeEnforceContext, employeeAccountId, uuid.New().String(), "employee", companyId)
	if err != nil {
		panic(fmt.Sprintf("Failed to enforce policy: %s", err))
	}

	if !authorized {
		fmt.Println("Employee user is not authorized")
	} else {
		fmt.Println("Employee user is authorized")
	}
}

func AddEmployeeToCompany(enforcer *casbin.Enforcer, accountId string, companyId string, role string) string {
	employeeId := "employee_" + uuid.New().String()

	// Your account connection to company, with a role
	_, err := enforcer.AddPolicy(accountId, companyId, role)
	if err != nil {
		panic(fmt.Sprintf("Failed to add policy: %s", err))
	}

	// Your account connection to employee, in a domain "company"
	_, err = enforcer.AddNamedPolicy("p2", accountId, employeeId, role, companyId)
	if err != nil {
		panic(fmt.Sprintf("Failed to add policy: %s", err))
	}

	if err = enforcer.SavePolicy(); err != nil {
		panic(fmt.Sprintf("Failed to save policy: %s", err))
	}

	return employeeId
}

func ClearPolicies() {
	// Define connection string
	connStr := "user=casbin_user password=casbin_password dbname=casbin host=localhost sslmode=disable"

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
	_, err = db.Exec("DROP TABLE IF EXISTS public.casbin_rule")
	if err != nil {
		log.Fatalf("Error deleting table: %v", err)
	}

	fmt.Println("Table public.casbin_role deleted successfully.")
}

func NewCasbinEnforcer() (*casbin.Enforcer, error) {
	a, err := xormadapter.NewAdapter("postgres", "user=casbin_user password=casbin_password host=127.0.0.1 port=5432 sslmode=disable") // Your driver and data source.
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

// AuthorizeEmployeeInCompany checks if the account has the role in the company
// Note: EmployeeId comes from parameters in requests
func AuthorizeEmployeeInCompany(accountId string, employeeId string, companyId string, role string /*todo enum*/) (bool, error) {
	enforcer, err := NewCasbinEnforcer() // todo dependency inject
	if err != nil {
		return false, err
	}

	enforcerContext := casbin.NewEnforceContext("2")

	//Enforce employee rights in company
	authorized, err := enforcer.Enforce(enforcerContext, accountId, employeeId, role, companyId)
	if err != nil {
		return false, err
	}

	return authorized, nil
}

// AuthorizeCompany checks if the account has the role in the company
func AuthorizeCompany(accountId string, companyId string, role string /*todo enum*/) (bool, error) {
	enforcer, err := NewCasbinEnforcer() // todo dependency inject
	if err != nil {
		return false, err
	}

	authorized, err := enforcer.Enforce(accountId, companyId, role)
	if err != nil {
		return false, err
	}

	return authorized, nil
}
