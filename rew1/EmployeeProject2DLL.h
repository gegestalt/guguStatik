#include <string>
using namespace std;
struct ProjectNode {
    string project_name;
    int project_priority;
    ProjectNode *next;
    ProjectNode *prev;

    ProjectNode(string name, int priority) : project_name(name), project_priority(priority), next(nullptr), prev(nullptr) {}
};

struct EmployeeNode {
    string employee_name;
    ProjectNode *head;
    ProjectNode *tail;
    EmployeeNode *down;

    EmployeeNode(string name) : employee_name(name), head(nullptr), tail(nullptr), down(nullptr) {}
};

class EmployeeProject2DLL {
private:
    EmployeeNode *head = nullptr;

public:
    EmployeeProject2DLL() noexcept; 

    bool isEmployeeAssignedToProject(string employee_name, string project_name);
    bool updateProjectPriority(string employee_name, string project_name, int& project_priority);
    bool assignEmployeeToProject(string employee_name, string project_name, int project_priority);
    void withdrawEmployeeFromProject(string employee_name, string project_name, int& project_priority);
    void printTheEntireList();
    void printEmployeeProjects(string employee_name, int order);
    void undo(char operation, string employee_name, string project_name, int project_priority);
    void clear();
};