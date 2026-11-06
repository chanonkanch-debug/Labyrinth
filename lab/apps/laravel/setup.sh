#!/bin/sh
# Builds a stock Laravel app in ./app and applies the lab overlay.
set -e
cd "$(dirname "$0")"
[ -d app ] || composer create-project --no-interaction --no-dev --prefer-dist laravel/laravel app "^12.0"
cp -r overlay/routes overlay/bootstrap app/
cd app
sed -i 's/^SESSION_DRIVER=.*/SESSION_DRIVER=cookie/; s/^APP_DEBUG=.*/APP_DEBUG=false/' .env
php artisan key:generate --force >/dev/null
php artisan config:clear >/dev/null
