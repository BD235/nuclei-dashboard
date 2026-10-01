import os

CONFIG = {
    "redis": {
        "host": os.getenv("REDIS_HOST", "127.0.0.1"),
        "port": int(os.getenv("REDIS_PORT", "6379")),
        "password": os.getenv("REDIS_PASSWORD", None),
    },
    "queues": {
        "fast_track": "queue:fast_track",
        "tech_targeted": "queue:tech_targeted",
        "deep_track": "queue:deep_track",
        "findings": "channel:findings",
    },
    "tech_tag_map": [
        {"match": "WordPress", "tag": "wordpress,wp-plugin"},
        {"match": "Spring", "tag": "springboot,spring"},
        {"match": "Laravel", "tag": "laravel"},
        {"match": "Apache", "tag": "apache"},
        {"match": "Nginx", "tag": "nginx"},
        {"match": "PHP", "tag": "php"},
        {"match": "Tomcat", "tag": "tomcat"},
        {"match": "Node", "tag": "nodejs"},
        {"match": "Express", "tag": "nodejs,express"},
        {"match": "Django", "tag": "django,python"},
        {"match": "Flask", "tag": "flask,python"},
        {"match": "Drupal", "tag": "drupal"},
        {"match": "Joomla", "tag": "joomla"},
    ]
}
