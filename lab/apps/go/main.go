// Go (net/http) lab app implementing the Labyrinth lab contract (see lab/README.md).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type item struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

var (
	items    = []item{{1, "Widget"}, {2, "Gadget"}}
	sessions = map[string]string{}
	mu       sync.Mutex
	upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func user(r *http.Request) string {
	c, err := r.Cookie("sid")
	if err != nil {
		return ""
	}
	mu.Lock()
	defer mu.Unlock()
	return sessions[c.Value]
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "framework": "go"})
	})
	mux.HandleFunc("GET /api/items", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, items) })
	mux.HandleFunc("GET /api/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		for _, it := range items {
			if fmt.Sprint(it.ID) == r.PathValue("id") {
				writeJSON(w, 200, it)
				return
			}
		}
		writeJSON(w, 404, map[string]string{"error": "not found"})
	})
	mux.HandleFunc("POST /api/items", func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{}
		json.NewDecoder(r.Body).Decode(&body)
		body["id"] = 3
		writeJSON(w, 201, body)
	})
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<form method="post" action="/login"><input name="username"><input name="password" type="password"><button>Sign in</button></form>`)
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("username") == "alice" && r.FormValue("password") == "wonderland" {
			b := make([]byte, 16)
			rand.Read(b)
			sid := hex.EncodeToString(b)
			mu.Lock()
			sessions[sid] = "alice"
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, HttpOnly: true, SameSite: http.SameSiteLaxMode, Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark", Path: "/"})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		w.WriteHeader(401)
		io.WriteString(w, "invalid credentials")
	})
	mux.HandleFunc("GET /dashboard", func(w http.ResponseWriter, r *http.Request) {
		if u := user(r); u != "" {
			fmt.Fprintf(w, "<h1>Welcome %s</h1>", u)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	mux.HandleFunc("POST /checkout", func(w http.ResponseWriter, r *http.Request) {
		if user(r) != "" {
			writeJSON(w, 200, map[string]any{"ok": true, "order": 1001})
			return
		}
		writeJSON(w, 401, map[string]string{"error": "login required"})
	})
	mux.HandleFunc("POST /upload", func(w http.ResponseWriter, r *http.Request) {
		f, h, err := r.FormFile("file")
		if err != nil {
			writeJSON(w, 200, map[string]int{"size": 0})
			return
		}
		f.Close()
		writeJSON(w, 200, map[string]int64{"size": h.Size})
	})
	mux.HandleFunc("GET /redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/health", http.StatusFound)
	})
	mux.HandleFunc("GET /stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		for n := 1; n <= 3; n++ {
			fmt.Fprintf(w, "data: tick %d\n\n", n)
			fl.Flush()
			time.Sleep(500 * time.Millisecond)
		}
	})
	mux.HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			t, m, err := c.ReadMessage()
			if err != nil {
				return
			}
			c.WriteMessage(t, append([]byte("echo:"), m...))
		}
	})
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	log.Println("go lab app on", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
