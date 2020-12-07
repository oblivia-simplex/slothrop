from julia:1.5.3

RUN apt-get update
RUN apt-get install -y python3 python3-pip
RUN pip3 install angr

RUN mkdir /root/Slothrop
WORKDIR /root/Slothrop

# COPY . . 

CMD [ "julia" ]
