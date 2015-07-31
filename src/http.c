#include "http.h"

static CURL *curl;

void http_init() {
    curl = curl_easy_init();

    // start cookie engine
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
}

void http_destroy() {
    curl_easy_cleanup(curl);
    curl_global_cleanup();
}

static size_t block_to_string(void *buffer, size_t size, size_t nmemb, bstring *str)
{
    // create base empty string if it doesn't exist
    if (*str == NULL) { *str = cstr2bstr(""); }

    int res = bcatblk(*str, buffer, (int) (size * nmemb));
    check(res == BSTR_OK, "writing page block to string failed");

    error:
    return size * nmemb;
}

bstring http_get(char *url)
{
    /* set content type */
    struct curl_slist *headers = NULL;
    CURLcode res;
    bstring data = NULL;

    headers = curl_slist_append(headers, "Accept: application/json");
    //headers = curl_slist_append(headers, "Content-Type: application/json");
    if (curl) {

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, block_to_string);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        res = curl_easy_perform(curl);
        check(res == CURLE_OK, "Get to %s unsuccessful.", url);

        debug("%s\n", bdata(data));

    }

    error:
    curl_slist_free_all(headers);
    return data;
}

bstring http_post(char *url, bstring *post)
{
    /* set content type */
    struct curl_slist *headers = NULL;
    CURLcode res;
    bstring data = NULL;

    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (curl) {

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, bdata(*post));
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, block_to_string);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        res = curl_easy_perform(curl);
        check(res == CURLE_OK, "Post to %s unsuccessful.", url);

        debug("%s\n", bdata(data));

    }

    error:
    curl_slist_free_all(headers);
    return data;
}

bstring http_put(char *url, bstring *post)
{
    /* set content type */
    struct curl_slist *headers = NULL;
    CURLcode res;
    bstring data = NULL;

    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (curl) {

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, bdata(*post));
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, block_to_string);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        res = curl_easy_perform(curl);
        check(res == CURLE_OK, "Post to %s unsuccessful.", url);

        debug("%s\n", bdata(data));

    }

    error:
    curl_slist_free_all(headers);
    return data;
}