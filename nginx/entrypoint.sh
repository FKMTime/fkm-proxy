/bin/proxy-server &

if [ ! -f /etc/nginx/conf.d/default.conf ]; then
    envsubst "$(printf '${%s} ' $(env | cut -d'=' -f1))" < /etc/nginx/conf.template > /etc/nginx/conf.d/default.conf

    nginx
    certbot --nginx -n --agree-tos -m $EMAIL -d $DOMAIN
    nginx -s quit
fi

nginx -g "daemon off;"
