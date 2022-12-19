FROM php:8.2-alpine
RUN apk update && apk add --no-cache gmp-dev linux-headers
RUN mkdir -p /usr/src/php/ext/xdebug && \
    curl -fsSL https://pecl.php.net/get/xdebug-3.2.0.tgz | tar xvz -C "/usr/src/php/ext/xdebug" --strip 1
RUN docker-php-ext-install gmp xdebug
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
