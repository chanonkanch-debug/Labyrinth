FROM php:8.3-cli
RUN apt-get update && apt-get install -y --no-install-recommends git unzip libzip-dev libsqlite3-dev && docker-php-ext-install zip && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
WORKDIR /lab
COPY overlay ./overlay
RUN cp overlay/uploads.ini /usr/local/etc/php/conf.d/uploads.ini
COPY setup.sh .
RUN ./setup.sh
WORKDIR /lab/app
ENV PHP_CLI_SERVER_WORKERS=8
EXPOSE 8000
CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=8000"]
