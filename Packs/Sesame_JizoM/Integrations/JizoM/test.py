import requests

response = requests.get(
    "https://172.32.1.106:10633/ping",
    headers={
        "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpYXQiOjE3MDk1Njg5MDYsImV4cCI6MTcwOTU4MzMwNiwicm9sZXMiOlsiUk9MRV9PUEVSQVRPUiJdLCJ1c2VybmFtZSI6Im9wZXJhdG9yIn0.fZ4idn887HMShItALLd0bGghmgxbRJGVLwVtGf1eKmUePN6XA2Mm2rbhRYLLYeqpMSY8qrPS6sNk7CHYohgaKs_ACzHmO0SD19F3sRR2WZeNZQbZs0y0Wok6oo1bwM9AO4NQZO3FlCdzzZhw6C388f9OMskiMBMQiW7UZiga5UMW4_rbI95VCO5cGV8bb0JxmmAbL8j_dQQ7ne_UerYsVPACuwsbAhddmaU6zuKx9PxwRtlSoQJOXJZRwOa1GJXC3pG8WhhVY6LdHgGR21lqEKkXuQBWKNQrcVr1cDEA8LaIiWFGZ3Ajfx_MqxA-dQWvlyF8yMAKDKavthodMW6m8A"
    },
)




