from julia:1.5.3

RUN apt-get update
RUN apt-get install -y python3 python3-pip
RUN pip3 install angr

RUN mkdir -p /root/.julia/config
COPY startup.jl /root/.julia/config/startup.jl

RUN mkdir /root/Slothrop
WORKDIR /root/Slothrop

CMD [ "julia", "-q", "--project", "-p 4" ]
