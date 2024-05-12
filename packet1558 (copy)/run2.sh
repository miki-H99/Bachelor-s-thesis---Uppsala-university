#!/bin/bash --login

echo -n "Are you a slave or master?: "
read designated_role

echo -n "For how long do you want the ptp4l daemon to run (in minutes)?: "
read Run_time

echo "The ptp4l daemon will run for $Run_time min"

fname=""
trial_number=""

while true; do
    if [ "$designated_role" = "s" ]; then
        echo -n "Enter the IP address of the master clock you want to connect to: "
        read connecting_IP
        echo "This computer will connect to: $connecting_IP"

        echo -n "Which trial as a slave is this?: "
        read trial_number
    else
        echo -n "Which trial as a master is this?: "
        read trial_number
    fi

    if [[ -e "./Timed_Results/TestTime_nr_${trial_number}.txt" ]]; then
        echo "A file for trial number ${trial_number} already exists."
    else
        echo "A file named TestTime_nr_${trial_number}.txt is being created!"
        fname="TestTime_nr_${trial_number}.txt"
        export FILE_NAME=$fname

        if [ "$designated_role" = "s" ]; then
            sudo ptp4l -i enp1s0 -s $connecting_IP -m -S  >> "./Timed_Results/$fname" & break   
        else
            sudo ptp4l -i enp1s0 -m -S >> "./Timed_Results/$fname" & break 
        fi

    fi 
done

sleep ${Run_time}m
export DURATION=$Run_time

sudo kill -9 `ps -ef | grep ptp4l | grep -v grep | awk '{print $2}'`
#echo "The ptp4l process terminated safely.\n"

#echo "Plot is being created and running...\n"
./Txt2Plot.py

#echo "All processes have been terminated safely!\n"
#echo "Program exiting..."

exit 0

