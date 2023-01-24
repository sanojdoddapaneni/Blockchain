package main

import "fmt"

func main() {
	fmt.Println("hello world")

	sum := 0
	for i := 0; i < 10; i++ {
		fmt.Println(sum)
		sum += i
	}

	fmt.Println(sum)
}
