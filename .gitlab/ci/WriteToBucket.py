from google.cloud import storage
import threading

mutex = threading.Lock()


def write_to_gcs_with_mutex(data, bucket_name, file_name):
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(file_name)

    with mutex:
        with blob.open("w") as f:
            f.write(data)


if __name__ == "__main__":
    print("starting to write to the bucket")
    write_to_gcs_with_mutex("Hello World!", "https://console.cloud.google.com/storage/browser/", "file.txt")
