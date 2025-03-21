#!/bin/sh

if [ ! -f /etc/XrayR/config.yml ]; then
    echo "配置不存在，复制全部默认配置..."
    cp -r /home/* /etc/XrayR/
else
    echo "配置已存在，仅复制除 config.yml 外的其他文件..."
    for file in /home/*; do
        [ "$(basename "$file")" != "config.yml" ] && cp -r "$file" /etc/XrayR/
    done
fi

exec XrayR --config /etc/XrayR/config.yml