const Tour = require("../models/tourModel");

//route handlers
exports.getAllTours = (req, res) => {
    res.json({
        status: "success",
        // data: {
        //     tours,
        // },
    });
};

exports.getTour = (req, res) => {
    // const id = req.params.id * 1;
    // const tour = tours.find((el) => el.id === id);

    // if (!tour) {
    //     return res.status(404).json({ status: "fail", message: "Invalid ID" });
    // }

    res.json({
        status: "success",
        // data: {
        //     tour,
        // },
    });
};

exports.createTour = (req, res) => {
    res.status(201).json({
        status: "success",
        // data: {
        //     tour: newTour,
        // },
    });
};

exports.updateTour = (req, res) => {
    res.status(200).json({
        status: "success",
        // data: {
        //     tour: "<UPDATED TOUR>",
        // },
    });
};



exports.checkBody = (req, res, next) => {
    if (!req.body.name || req.body.price) {
        return res.status(400).json({
            status: "fail",
            message: "Missing name or price",
        });
    }
    next();
};

exports.deleteTour = (req, res) => {
    res.status(204).json({
        status: "success",
        // data: null,
    });
};