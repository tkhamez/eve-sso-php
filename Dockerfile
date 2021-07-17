FROM php:8.0-alpine
RUN apk update && apk add --no-cache gmp-dev
RUN docker-php-ext-install gmp
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
