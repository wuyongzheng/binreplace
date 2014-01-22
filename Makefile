binreplace: binreplace.c
	gcc -DNDEBUG -Wall -O -o binreplace binreplace.c
binreplace.d: binreplace.c
	gcc -Wall -g -o binreplace.d binreplace.c

.PHONY: clean
clean:
	rm -f binreplace binreplace.d

.PHONY: test
test: binreplace
	./binreplace -r d f -r pq qq -r p x < test1.in | diff test1.out -
	./binreplace -r '3\n4' '34' -r 123 '12\n3' < test2.in | diff test2.out -
	./binreplace -d ATP < test3.in | diff test3.out -
	./binreplace -f test4.list < test4.in | diff test4.out -
	./binreplace -r '\xEF\xAC\x80' ff -r '\xEF\xAC\x81' fi -r '\xEF\xAC\x82' fl < test5.in | diff test5.out -
	./binreplace -R EFAC80 6666 -R EFAC81 6669 -R EFAC82 666c < test5.in | diff test5.out -
