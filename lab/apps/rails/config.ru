# Rails lab app (single file) implementing the Labyrinth lab contract (see lab/README.md).
# Real Rails CSRF protection (with Origin checking) and cookie sessions. No websocket (ActionCable not wired up).
require "rails"
require "action_controller/railtie"

class LabApp < Rails::Application
  config.root = __dir__
  config.secret_key_base = "lab-only-not-a-secret" * 4
  config.eager_load = false
  config.hosts.clear
  config.logger = Logger.new($stdout)
  config.log_level = :warn
  config.session_store :cookie_store, key: "_lab_session"
  config.action_controller.forgery_protection_origin_check = true
  routes.append do
    get "/api/health", to: "lab#health"
    get "/api/items", to: "lab#items"
    get "/api/items/:id", to: "lab#item"
    post "/api/items", to: "lab#create"
    get "/login", to: "lab#login_form"
    post "/login", to: "lab#login"
    get "/dashboard", to: "lab#dashboard"
    post "/checkout", to: "lab#checkout"
    post "/upload", to: "lab#upload"
    get "/redirect", to: "lab#redir"
    get "/stream", to: "lab#stream"
  end
end

ITEMS = [{ id: 1, name: "Widget" }, { id: 2, name: "Gadget" }].freeze

class LabController < ActionController::Base
  include ActionController::Live
  protect_from_forgery with: :exception
  skip_forgery_protection only: %i[create checkout upload]

  def health = render(json: { ok: true, framework: "rails" })
  def items = render(json: ITEMS)

  def item
    it = ITEMS.find { |i| i[:id].to_s == params[:id] }
    it ? render(json: it) : render(json: { error: "not found" }, status: 404)
  end

  def create = render(json: { id: 3 }.merge(JSON.parse(request.raw_post)), status: 201)

  def login_form
    render html: %(<form method="post" action="/login"><input type="hidden" name="authenticity_token" value="#{form_authenticity_token}"><input name="username"><input name="password" type="password"><button>Sign in</button></form>).html_safe
  end

  def login
    if params[:username] == "alice" && params[:password] == "wonderland"
      session[:user] = "alice"
      cookies[:theme] = "dark"
      redirect_to "/dashboard", status: 302
    else
      render plain: "invalid credentials", status: 401
    end
  end

  def dashboard
    session[:user] ? render(html: "<h1>Welcome #{session[:user]}</h1>".html_safe) : redirect_to("/login", status: 302)
  end

  def checkout
    session[:user] ? render(json: { ok: true, order: 1001 }) : render(json: { error: "login required" }, status: 401)
  end

  def upload = render(json: { size: params[:file]&.size || 0 })
  def redir = redirect_to("/api/health", status: 302)

  def stream
    response.headers["Content-Type"] = "text/event-stream"
    response.headers["Last-Modified"] = Time.now.httpdate # stops Rack::ETag buffering the stream
    3.times { |i| response.stream.write("data: tick #{i + 1}\n\n"); sleep 0.5 }
  ensure
    response.stream.close
  end
end

LabApp.initialize!
run LabApp
