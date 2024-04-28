#include <iostream> 
#include <vector>   
#include <random>   
#include <ctime>    
using namespace std; 
class Solution {
public:
    double radius, x_center, y_center;

    
    Solution(double radius_, double x_center_, double y_center_)
        : radius(radius_), x_center(x_center_), y_center(y_center_) {}

    
    vector<double> randPoint() {
        // Use a modern random number generator (seeded with current time)
        static default_random_engine generator(time(nullptr));
        uniform_real_distribution<double> theta_dist(0, 2 * M_PI);
        uniform_real_distribution<double> radius_dist(0, radius);

        double theta = theta_dist(generator);
        double rand_radius = radius_dist(generator);

        double x_rand = x_center + rand_radius * cos(theta);
        double y_rand = y_center + rand_radius * sin(theta);

        return {x_rand, y_rand};
    }
};

int main() {
    
    Solution solution(1.0, 0.0, 0.0);
    for (int i = 0; i < 5; ++i) {
        vector<double> point = solution.randPoint();
        cout << "Point " << i + 1 << ": [" << point[0] << ", " << point[1] << "]" << endl;
    }

    return 0;
}
