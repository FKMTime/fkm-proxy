if [ -z "$TOKEN" ]; then
    echo "Token is required"
    exit 0
fi

/bin/proxy-client &
nginx -g "daemon off;"
