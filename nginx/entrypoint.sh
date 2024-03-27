if [ -z "$TOKEN" ] || [ -z "$HASH" ]; then
    echo "Token and Hash are required"
    exit 0
fi

/bin/proxy-client &
nginx -g "daemon off;"
