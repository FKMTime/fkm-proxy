if [ -z "$TOKEN" ]; then
    echo "TOKEN is required for proxy client"
else
    /bin/proxy-client &
fi

nginx -g "daemon off;"
