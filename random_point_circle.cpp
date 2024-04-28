    
#include <iostream>
#include <vector>
#include <cstdlib> 
#include <cmath> 
using namespace std; 

class Solution {
public:
    double r, x, y;
    Solution(double radius, double x_center, double y_center) {
        r = radius, x = x_center, y = y_center;
    }
        vector<double> randPoint() {
        ios_base::sync_with_stdio(0), cin.tie(0), cout.tie(0);
        double theta = ((double)rand() / RAND_MAX) * 2 * M_PI;
        double rand_radius = sqrt(((double)rand() / RAND_MAX)) * r; 
        double x_rand = x + rand_radius * cos(theta);
        double y_rand = y + rand_radius * sin(theta);
        return {x_rand, y_rand};
    }
};

int main(int argc, char const *argv[])
{
    
    return 0;
}
