TARGET := ts_parser

CXX     := g++
CFLAGS  := -Wall -O0 -g3
CXXFLAGS := -Wall -O0 -g3 -std=c++11
SOURCE := $(wildcard *.cpp)
OBJS   := $(patsubst %.cpp, %.o, $(SOURCE))

all: $(TARGET)
$(TARGET) : $(OBJS)
	$(CXX) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(TARGET)

.PHONY: clean

clean:
	rm -f $(TARGET) $(OBJS) *.o
