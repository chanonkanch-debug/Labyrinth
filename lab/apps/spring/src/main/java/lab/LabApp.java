// Spring Boot lab app implementing the Labyrinth lab contract (see lab/README.md).
package lab;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.*;
import java.util.concurrent.Executors;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.config.annotation.*;
import org.springframework.web.socket.handler.TextWebSocketHandler;

@SpringBootApplication
@RestController
public class LabApp {
  static final List<Map<String, Object>> ITEMS = List.of(Map.of("id", 1, "name", "Widget"), Map.of("id", 2, "name", "Gadget"));

  public static void main(String[] args) { SpringApplication.run(LabApp.class, args); }

  @GetMapping("/api/health") Map<String, Object> health() { return Map.of("ok", true, "framework", "spring"); }

  @GetMapping("/api/items") List<Map<String, Object>> items() { return ITEMS; }

  @GetMapping("/api/items/{id}") ResponseEntity<?> item(@PathVariable int id) {
    return ITEMS.stream().filter(i -> i.get("id").equals(id)).findFirst()
        .<ResponseEntity<?>>map(ResponseEntity::ok)
        .orElse(ResponseEntity.status(404).body(Map.of("error", "not found")));
  }

  @PostMapping("/api/items") ResponseEntity<?> create(@RequestBody Map<String, Object> body) {
    var out = new HashMap<>(body); out.put("id", 3);
    return ResponseEntity.status(201).body(out);
  }

  @GetMapping(value = "/login", produces = MediaType.TEXT_HTML_VALUE) String loginForm() {
    return "<form method=\"post\" action=\"/login\"><input name=\"username\"><input name=\"password\" type=\"password\"><button>Sign in</button></form>";
  }

  @PostMapping("/login") ResponseEntity<?> login(@RequestParam String username, @RequestParam String password,
                                                 HttpSession session, HttpServletResponse resp) {
    if ("alice".equals(username) && "wonderland".equals(password)) {
      session.setAttribute("user", "alice");
      resp.addCookie(new Cookie("theme", "dark"));
      return ResponseEntity.status(302).header("Location", "/dashboard").build();
    }
    return ResponseEntity.status(401).body("invalid credentials");
  }

  @GetMapping(value = "/dashboard", produces = MediaType.TEXT_HTML_VALUE) ResponseEntity<?> dashboard(HttpSession session) {
    var u = session.getAttribute("user");
    return u != null ? ResponseEntity.ok("<h1>Welcome " + u + "</h1>") : ResponseEntity.status(302).header("Location", "/login").build();
  }

  @PostMapping("/checkout") ResponseEntity<?> checkout(HttpSession session) {
    return session.getAttribute("user") != null ? ResponseEntity.ok(Map.of("ok", true, "order", 1001))
        : ResponseEntity.status(401).body(Map.of("error", "login required"));
  }

  @PostMapping("/upload") Map<String, Object> upload(@RequestParam("file") MultipartFile file) {
    return Map.of("size", file.getSize());
  }

  @GetMapping("/redirect") ResponseEntity<?> redirect() { return ResponseEntity.status(302).header("Location", "/api/health").build(); }

  @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE) SseEmitter stream() {
    var em = new SseEmitter(10_000L);
    Executors.newSingleThreadExecutor().submit(() -> {
      try { for (int n = 1; n <= 3; n++) { em.send(SseEmitter.event().data("tick " + n)); Thread.sleep(500); } em.complete(); }
      catch (Exception e) { em.completeWithError(e); }
    });
    return em;
  }

  @Configuration @EnableWebSocket
  static class Ws implements WebSocketConfigurer {
    public void registerWebSocketHandlers(WebSocketHandlerRegistry reg) {
      reg.addHandler(new TextWebSocketHandler() {
        @Override protected void handleTextMessage(WebSocketSession s, TextMessage m) throws Exception {
          s.sendMessage(new TextMessage("echo:" + m.getPayload()));
        }
      }, "/ws").setAllowedOrigins("*");
    }
  }
}
