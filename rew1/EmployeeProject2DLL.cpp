    #include "EmployeeProject2DLL.h"
    #include <iostream>
    using namespace std;

    EmployeeNode* findEmployee(EmployeeNode* head, string employee_name) {
        if (head == nullptr) {
            return nullptr;
        }

        EmployeeNode* temp = head;
        while (temp != nullptr) {
            if (temp->employee_name == employee_name) {
                return temp;
            }
            temp = temp->down;
        }

        return nullptr;
    }

    ProjectNode* findProject(ProjectNode* head, string project_name) {
        ProjectNode* temp = head;
        while (temp != nullptr) {
            if (temp->project_name == project_name) {
                return temp;
            }
            temp = temp->next;
        }
        return nullptr;
    }


    EmployeeProject2DLL::EmployeeProject2DLL() noexcept: head(nullptr) {}


    bool EmployeeProject2DLL::isEmployeeAssignedToProject(string employee_name, string project_name) {
        EmployeeNode* employee = findEmployee(head, employee_name);
        if (employee == nullptr) {
            return false;
        }
        ProjectNode* project = findProject(employee->head, project_name);
        return project != nullptr;
    }

    bool EmployeeProject2DLL::updateProjectPriority(string employee_name, string project_name, int& project_priority) {
        EmployeeNode* employee = findEmployee(head, employee_name);
        if (employee == nullptr) {
            return false;
        }
        ProjectNode* project = findProject(employee->head, project_name);
        if (project == nullptr) {
            return false;
        }

        // Check if there is another project with the same priority
        ProjectNode* temp = employee->head;
        while (temp != nullptr) {
            if (temp->project_priority == project_priority && temp->project_name != project_name) {
                cout << "The project priority has not been updated because there is another project with the same priority." << endl;
                return false;
            }
            temp = temp->next;
        }

        // Check if the existing assignment's priority is the same as the parameter priority
        if (project->project_priority == project_priority) {
            cout << "The project priority is already the same as the new priority." << endl;
            return false;
        }

        // Update the priority of the project and reorder the list if needed
        int old_priority = project->project_priority;
        project->project_priority = project_priority;

        // Remove the project from its current position in the list
        if (project->prev != nullptr) {
            project->prev->next = project->next;
        } else {
            employee->head = project->next;
        }
        if (project->next != nullptr) {
            project->next->prev = project->prev;
        }

        // Find the correct position for the project in the list
        ProjectNode* current = employee->head;
        ProjectNode* previous = nullptr;
        while (current != nullptr && current->project_priority < project_priority) {
            previous = current;
            current = current->next;
        }

        // Insert the project at the correct position
        project->next = current;
        project->prev = previous;
        if (previous != nullptr) {
            previous->next = project;
        } else {
            employee->head = project;
        }
        if (current != nullptr) {
            current->prev = project;
        }

        // Return the old priority
        project_priority = old_priority;

        return true;
    }



 bool EmployeeProject2DLL::assignEmployeeToProject(string employee_name, string project_name, int project_priority) {
    EmployeeNode* employee = findEmployee(head, employee_name);
    if (employee == nullptr) {
        employee = new EmployeeNode(employee_name);
        if (head == nullptr || head->employee_name > employee_name) {
            employee->down = head;
            head = employee;
        } else {
            EmployeeNode* current = head;
            while (current->down != nullptr && current->down->employee_name < employee_name) {
                current = current->down;
            }
            employee->down = current->down;
            current->down = employee;
        }
    }
    
    ProjectNode* project = findProject(employee->head, project_name);
    if (project != nullptr) {
        project->project_priority = project_priority;
        return true;
    }

    // Check if there is another project with the same priority
    ProjectNode* temp = employee->head;
    while (temp != nullptr) {
        if (temp->project_priority == project_priority) {
            cout << "The project has not been added because there is another project with the same priority." << endl;
            return false;
        }
        temp = temp->next;
    }

    project = new ProjectNode(project_name, project_priority);
    if (employee->head == nullptr || employee->head->project_priority >= project_priority) {
        project->next = employee->head;
        if (employee->head != nullptr) {
            employee->head->prev = project;
        }
        employee->head = project;
    } else {
        ProjectNode* current = employee->head;
        while (current->next != nullptr && current->next->project_priority < project_priority) {
            current = current->next;
        }
        project->next = current->next;
        if (current->next != nullptr) {
            current->next->prev = project;
        }
        current->next = project;
        project->prev = current;
    }
    return true;
}


    void EmployeeProject2DLL::withdrawEmployeeFromProject(string employee_name, string project_name, int& project_priority) {
        EmployeeNode* employee = findEmployee(head, employee_name);
        if (employee == nullptr) {
            return;
        }
        ProjectNode* project = findProject(employee->head, project_name);
        if (project == nullptr) {
            return;
        }
        if (project->prev != nullptr) {
            project->prev->next = project->next;
        } else {
            employee->head = project->next;
        }
        if (project->next != nullptr) {
            project->next->prev = project->prev;
        }
        project_priority = project->project_priority;
        delete project;
    }

    void EmployeeProject2DLL::printTheEntireList() {
        if (head == nullptr) {
            cout << "The list is empty." << endl;
            return;
        }

        bool isEmpty = true;
        EmployeeNode* tempEmployee = head;
        while (tempEmployee != nullptr) {
            if (tempEmployee->head != nullptr) {
                isEmpty = false;
                cout << tempEmployee->employee_name << ": ";
                ProjectNode* tempProject = tempEmployee->head;
                while (tempProject != nullptr) {
                    cout << "(" << tempProject->project_name << ", " << tempProject->project_priority << ") ";
                    tempProject = tempProject->next;
                }
                cout << endl;
            }
            tempEmployee = tempEmployee->down;
        }

        if (isEmpty) {
            cout << "The list is empty." << endl;
        }
    }
    void EmployeeProject2DLL::printEmployeeProjects(string employee_name, int order) {
    if (head == nullptr) {
        cout << "There are no employees in the list." << endl;
        return;
    }

    EmployeeNode* employee = findEmployee(head, employee_name);
    if (employee == nullptr) {
        cout << "The employee is not in the list." << endl;
        return;
    }

    if (employee->head == nullptr) {
        cout <<"There are no employees in the list."<< endl;
        return;
    }


    int start;
    int end;
    int step;
    if (order == 1) {
        start = 1;
        end = 101;
        step = 1;
    } else {
        start = 100;
        end = 0;
        step = -1;
    }

    ProjectNode* tempProject;
    for (int priority = start; ; priority += step) {
        if ((order == 1 && priority > end) || (order != 1 && priority < end)) {
            break;
        }

        tempProject = employee->head;
        while (tempProject != nullptr) {
            if (tempProject->project_priority == priority) {
                cout << "(" << tempProject->project_name << ", " << tempProject->project_priority << ") ";
            }
            tempProject = tempProject->next;
        }
    }
    cout << endl;
    }

    void EmployeeProject2DLL::undo(char operation, string employee_name, string project_name, int project_priority) {
    if (operation == 'a') {
        withdrawEmployeeFromProject(employee_name, project_name, project_priority);
        cout << "Undoing the assignment of a project." << endl;
    } else if (operation == 'w') {
        assignEmployeeToProject(employee_name, project_name, project_priority);
        cout << "Undoing the withdrawal of a project." << endl;
    } else if (operation == 'u') {
        EmployeeNode* employee = findEmployee(head, employee_name);
        if (employee != nullptr) {
            ProjectNode* project = findProject(employee->head, project_name);
            if (project != nullptr) {
                // Remove the project from its current position in the list
                if (project->prev != nullptr) {
                    project->prev->next = project->next;
                } else {
                    employee->head = project->next;
                }
                if (project->next != nullptr) {
                    project->next->prev = project->prev;
                }

                // Update the priority of the project
                project->project_priority = project_priority;

                // Find the correct position for the project in the list
                ProjectNode* current = employee->head;
                ProjectNode* previous = nullptr;
                while (current != nullptr && current->project_priority < project_priority) {
                    previous = current;
                    current = current->next;
                }

                // Insert the project at the correct position
                project->next = current;
                project->prev = previous;
                if (previous != nullptr) {
                    previous->next = project;
                } else {
                    employee->head = project;
                }
                if (current != nullptr) {
                    current->prev = project;
                }
            }
        }
        cout << "Undoing the update of a project priority." << endl;
    } else {
        cout << "Invalid operation." << endl;
    }

    // Check if the list is empty after undoing the operation
    if (head == nullptr) {
        cout << "The list is empty." << endl;
    }
}

    void EmployeeProject2DLL::clear() {
        while (head != nullptr) {
            EmployeeNode* tempEmployee = head;
            head = head->down;
            while (tempEmployee->head != nullptr) {
                ProjectNode* tempProject = tempEmployee->head;
                tempEmployee->head = tempEmployee->head->next;
                delete tempProject;
            }
            delete tempEmployee;
        }
    }