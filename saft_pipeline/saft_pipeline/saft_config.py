import os

replacements = dict()

# server where ros system is running
hostname = "localhost"
port = "22"
username = "something"
# key-pair is used for authentication

# path-/filenames
models_path = "src/models"
tools_path = "src/tools"
name_of_replacement_file = os.path.join(models_path,"dictionary.txt")
ATs_outputpath = "atLibs"
name_of_ros_dataflow_model = "ros.dataflow"
names_of_dataflow_models = [os.path.join(models_path,name_of_ros_dataflow_model),os.path.join(models_path,"manual.dataflow")]
name_of_combined_dataflow_model = os.path.join(models_path,"quadlab.dataflow")
name_of_ros_deployment_model = os.path.join(models_path,"ros.deployment")
name_of_manual_deployment_model = os.path.join(models_path,"manual.deployment")
name_of_deployment_enhanced_model = os.path.join(models_path,"quadlab_enhanced.deployment")
name_of_packages_file = os.path.join(models_path,"dep_packages.txt")
name_of_files_file = os.path.join(models_path,"dep_files.txt")
name_of_at_fullsearch = os.path.join(models_path,"at_fullsearch.json")
name_of_at_cpesearch = os.path.join(models_path,"at_cpesearch.json")
name_of_attack_fault_tree = os.path.join(models_path,"generatedAFTTextFile.attackFaultTree")
name_of_dft = "test.dft"

name_of_fault_tree = os.path.join(models_path,"injure.faultTree")
storm_docker_container_name = "storm2"
dft_file = os.path.join(models_path,name_of_dft)

url_of_cpesearch = "https://cpe-guesser.cve-search.org/search"
path_to_AT_generator = os.path.join(tools_path,"attackgraphgenerator")

list_of_temp_files = [name_of_ros_dataflow_model, 
                      name_of_combined_dataflow_model, 
                      name_of_ros_deployment_model, 
                      name_of_deployment_enhanced_model, 
                      name_of_packages_file, 
                      name_of_files_file, 
                      name_of_at_fullsearch, 
                      name_of_at_cpesearch,
                      name_of_attack_fault_tree,
                      dft_file]




