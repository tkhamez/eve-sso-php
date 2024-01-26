FROM php:8.3-alpine
RUN apk update && apk add --no-cache gmp-dev linux-headers
RUN mkdir -p /usr/src/php/ext/xdebug && \
    curl -fsSL https://pecl.php.net/get/xdebug-3.3.0.tgz | tar xvz -C "/usr/src/php/ext/xdebug" --strip 1
RUN docker-php-ext-install gmp xdebug
RUN echo "xdebug.mode = develop,coverage,profile,debug,trace"  > /usr/local/etc/php/conf.d/eve-sso.ini && \
    echo "xdebug.output_dir = /app/xdebug/output"             >> /usr/local/etc/php/conf.d/eve-sso.ini && \
    echo "xdebug.start_with_request = trigger"                >> /usr/local/etc/php/conf.d/eve-sso.ini && \
    echo "xdebug.client_host = 172.17.0.1"                    >> /usr/local/etc/php/conf.d/eve-sso.ini
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
