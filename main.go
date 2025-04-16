package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// User struct represents the user and their privileges
type User struct {
	Username   string
	Password   string
	Privileges []string
}

// QueryResult struct for holding query results
type QueryResult struct {
	Columns []string
	Results []map[string]interface{}
	Error   string
}

// connectDB establishes a connection to the MySQL database
func connectDB() {
	var err error
	db, err = sql.Open("mysql", "root:Lokesh@25@tcp(localhost:3306)/querybuilder")
	if err != nil {
		log.Fatalf("Failed to connect to MySQL: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	log.Println("Database connection established!")
}

// connectDBWithCredentials connects to MySQL with provided credentials
func connectDBWithCredentials(username, password string) (*sql.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(localhost:3306)/querybuilder", username, password)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MySQL: %v", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}
	return db, nil
}

// hashPassword hashes the password using bcrypt
func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// checkPassword compares a hashed password with a plain-text password
func checkPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// createMySQLUser creates a new user in the MySQL system and assigns privileges
func createMySQLUser(username, password string, privileges []string) error {
	_, err := db.Exec(fmt.Sprintf("CREATE USER '%s'@'localhost' IDENTIFIED BY '%s'", username, password))
	if err != nil {
		return fmt.Errorf("failed to create user: %v", err)
	}

	for _, privilege := range privileges {
		privilegeQuery := fmt.Sprintf("GRANT %s ON *.* TO '%s'@'localhost'", privilege, username)
		_, err = db.Exec(privilegeQuery)
		if err != nil {
			return fmt.Errorf("failed to grant privilege %s: %v", privilege, err)
		}
	}

	_, err = db.Exec("FLUSH PRIVILEGES")
	if err != nil {
		return fmt.Errorf("failed to flush privileges: %v", err)
	}

	log.Println("User created with selected privileges successfully!")
	return nil
}

// registerHandler handles the user registration and privilege assignment
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl := template.Must(template.ParseFiles("templates/register.html"))
		tmpl.Execute(w, nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	privileges := r.Form["privileges"]

	if len(privileges) == 0 {
		http.Error(w, "At least one privilege must be selected", http.StatusBadRequest)
		return
	}

	err := createMySQLUser(username, password, privileges)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create MySQL user: %v", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// loginHandler handles user login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	newDB, err := connectDBWithCredentials(username, password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	db = newDB
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// queryFormHandler renders the SQL query form
func queryFormHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/query_form.html"))
	tmpl.Execute(w, nil)
}

// executeQueryHandler executes the SQL query and displays the results
func executeQueryHandler(w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("query")
	if query == "" {
		http.Error(w, "Query cannot be empty", http.StatusBadRequest)
		return
	}

	if strings.HasPrefix(strings.ToUpper(query), "SELECT") && !strings.Contains(strings.ToUpper(query), "LIMIT") {
		query = query + " LIMIT 1000"
	}

	rows, err := db.Query(query)
	if err != nil {
		tmpl := template.Must(template.ParseFiles("templates/query_form.html"))
		tmpl.Execute(w, QueryResult{
			Error: fmt.Sprintf("Query execution failed: %v", err),
		})
		return
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		log.Fatalf("Failed to get columns: %v", err)
	}

	results := make([]map[string]interface{}, 0)
	colCount := len(columns)

	for rows.Next() {
		row := make([]interface{}, colCount)
		rowPtrs := make([]interface{}, colCount)
		for i := range row {
			rowPtrs[i] = &row[i]
		}

		if err := rows.Scan(rowPtrs...); err != nil {
			log.Fatalf("Failed to scan row: %v", err)
		}

		result := make(map[string]interface{})
		for i, col := range columns {
			value := row[i]
			if b, ok := value.([]byte); ok {
				value = string(b)
			}
			result[col] = value
		}
		results = append(results, result)
	}

	tmpl := template.Must(template.ParseFiles("templates/query_form.html"))
	tmpl.Execute(w, QueryResult{
		Columns: columns,
		Results: results,
		Error:   "",
	})
}

func main() {
	connectDB()
	defer db.Close()

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("templates/static"))))

	http.HandleFunc("/", queryFormHandler)
	http.HandleFunc("/execute-query", executeQueryHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)

	log.Println("Server started on http://localhost:8080/login")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
