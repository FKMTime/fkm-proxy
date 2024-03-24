if [ -z "$TOKEN" ] || [ -z "$HASH" ]; then
    nginx -g "daemon off;"
    exit 0
fi

/bin/proxy-server &

if [ ! -f /etc/nginx/conf.d/default.conf ]; then
    echo -e "\n\n\n\n\nGENERATING SSL CERTIFICATE\n\n\n\n\n"
    sleep 5

    envsubst "$(printf '${%s} ' $(env | cut -d'=' -f1))" < /etc/nginx/conf.template > /etc/nginx/conf.d/default.conf

    nginx
    certbot --nginx -n --agree-tos -m $EMAIL -d $DOMAIN
    nginx -s quit

    echo -e "\n\n\n\n\nSSL CERTIFICATE GENERATED\n\n\n\n\n"
    sleep 5
fi

nginx -g "daemon off;"
