pods=( $( kubectl get pods -A| grep -Ev "Running|Terminating"| tr -s " "| awk -F" " '{print $2}'|tail -n+2 ) )
pods1=( $( kubectl get pods -A| grep -Ev "Running|Terminating"| tr -s " "| awk -F" " '{print $1}'|tail -n+2 ) )
job=( $( kubectl get pods -A| grep "Completed"|tr -s " "| awk -F" " '{print $2}'|tail -n+1 ) )
for x in "${!pods[@]}";do
    if [[ "${job[*]}" =~  "${pods[x]}" ]];then
       echo "No issue"
    else
       echo "*******************************************************************"
       echo ${pods[x]}
       echo
       if [ "$1" == "a" ];then
          kubectl get event --namespace ${pods1[x]} --field-selector involvedObject.name=${pods[x]}
       else
           kubectl describe pods ${pods[x]} -n ${pods1[x]}
       fi
    fi
done
