<?php
// Laravel lab app implementing the Labyrinth lab contract (see lab/README.md).
// Real Laravel CSRF (VerifyCsrfToken) and encrypted cookie sessions. No websocket.

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

$items = [['id' => 1, 'name' => 'Widget'], ['id' => 2, 'name' => 'Gadget']];

Route::get('/api/health', fn () => ['ok' => true, 'framework' => 'laravel']);
Route::get('/api/items', fn () => $items);
Route::get('/api/items/{id}', function ($id) use ($items) {
    foreach ($items as $it) {
        if ((string) $it['id'] === $id) return $it;
    }
    return response()->json(['error' => 'not found'], 404);
});
Route::post('/api/items', fn (Request $r) => response()->json(['id' => 3] + $r->json()->all(), 201));
Route::get('/login', fn () => '<form method="post" action="/login"><input type="hidden" name="_token" value="'.csrf_token().'"><input name="username"><input name="password" type="password"><button>Sign in</button></form>');
Route::post('/login', function (Request $r) {
    if ($r->input('username') === 'alice' && $r->input('password') === 'wonderland') {
        $r->session()->put('user', 'alice');
        return redirect('/dashboard', 302)->withCookie(cookie('theme', 'dark'));
    }
    return response('invalid credentials', 401);
});
Route::get('/dashboard', fn (Request $r) => $r->session()->has('user')
    ? '<h1>Welcome '.$r->session()->get('user').'</h1>'
    : redirect('/login', 302));
Route::post('/checkout', fn (Request $r) => $r->session()->has('user')
    ? ['ok' => true, 'order' => 1001]
    : response()->json(['error' => 'login required'], 401));
Route::post('/upload', fn (Request $r) => ['size' => $r->file('file')?->getSize() ?? 0]);
Route::get('/redirect', fn () => redirect('/api/health', 302));
Route::get('/stream', fn () => response()->stream(function () {
    for ($n = 1; $n <= 3; $n++) {
        echo "data: tick $n\n\n";
        if (ob_get_level() > 0) ob_flush();
        flush();
        usleep(500000);
    }
}, 200, ['Content-Type' => 'text/event-stream', 'X-Accel-Buffering' => 'no']));
