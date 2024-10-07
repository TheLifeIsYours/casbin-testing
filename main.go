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

	orgId := "organization_" + uuid.New().String()
	companyId := "company_" + uuid.New().String()
	adminAccountId := "admin_" + uuid.New().String()

	AddEmployeeToCompany(enforcer, adminAccountId, companyId, "admin", orgId)

	//Auth user in organization
	enforcerContext := casbin.NewEnforceContext("")
	enforcerContext.RType = "r2"
	enforcerContext.MType = "m2"

	authorized, err := enforcer.Enforce(enforcerContext, adminAccountId, companyId, orgId)
	if err != nil {
		panic(fmt.Sprintf("Failed to enforce policy: %s", err))
	}
	if !authorized {
		fmt.Println("Admin user is not authorized to organization")
	} else {
		fmt.Println("Admin user is authorized to organization")
	}

	//Auth user in company - we don't have the orgId for this endpoint
	enforcerContext.RType = "r3"
	enforcerContext.MType = "m3"

	authorized, err = enforcer.Enforce(enforcerContext, adminAccountId, companyId)
	if err != nil {
		panic(fmt.Sprintf("Failed to enforce policy: %s", err))
	}

	if !authorized {
		fmt.Println("Admin user is not authorized to company")
	} else {
		fmt.Println("Admin user is authorized to company")
	}

	//Auth Role admin in company
	enforcerContext.RType = "r4"
	enforcerContext.MType = "m4"
	authorized, err = enforcer.Enforce(enforcerContext, adminAccountId, "admin", companyId)
	if err != nil {
		panic(fmt.Sprintf("Failed to enforce policy: %s", err))
	}

	if !authorized {
		fmt.Println("Admin user is not authorized as admin in company")
	} else {
		fmt.Println("Admin user is authorized as admin in company")
	}
}

func AddEmployeeToCompany(enforcer *casbin.Enforcer, accountId string, companyId string, role string, orgId string) string {
	employeeId := "employee_" + uuid.New().String()

	// Your account connection to employee, in a domain "company"
	_, err := enforcer.AddNamedPolicy("p", accountId, employeeId, role, companyId, orgId)
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
