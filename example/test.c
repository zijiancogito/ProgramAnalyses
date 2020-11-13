int sum(int a, int b) {
	return a+b;
}
int main() {
	int a = 1;
	int b = 2;
	int c =  sum(a,b);
	if (c>10){
		c = 10;
	}
	return c;
}
