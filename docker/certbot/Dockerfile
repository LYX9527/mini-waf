FROM certbot/certbot:latest

# certbot-dns-dnspod / certbot-dns-aliyun 等社区插件依赖 zope.interface
# 新版 certbot 镜像不再预装，需手动补充
RUN pip install --no-cache-dir \
    zope.interface \
    certbot-dns-cloudflare \
    certbot-dns-dnspod \
    certbot-dns-aliyun
